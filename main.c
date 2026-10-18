#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <signal.h>
#include <time.h>

#include <sodium/utils.h>
#include <tox/tox.h>

#define TUN_READ_BUF_SIZE 65535
#define STANDBY_TIMEOUT_US 5000000ull

/* Custom-packet prefix bytes. Tox reserves lossy IDs 192-199 (0xC0-0xC7)
   for AV/RTP, so custom lossy packets must start at 200 (0xC8). */
#define PACKET_PREFIX_LOSSLESS 160
#define PACKET_PREFIX_LOSSY    200

struct app_data
{
	Tox* tox;
	uint64_t last_tox_activity_time;
	int create;
	char tox_file[256];
	uint8_t friend_pubkey[TOX_PUBLIC_KEY_SIZE];
	int usage_only;
	int add_friend;
	int del_friend;
	int connect;

	char tun_name[IFNAMSIZ];
	int tun_fd;
	int use_lossy;

	uint32_t friend_number;

	uint8_t tun_buf[TUN_READ_BUF_SIZE];
};

static volatile sig_atomic_t quit_requested = 0;

static void signal_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
	{
		quit_requested = 1;
	}
}

static uint64_t monotonic_now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

static void print_usage(void)
{
	fprintf(stderr, "Usage: toxtun -t <tox_file>                        Show profile and friends, then exit\n");
	fprintf(stderr, "       toxtun -n -t <tox_file>                     Create new tox file and exit\n");
	fprintf(stderr, "       toxtun -f <tox_address>|<public_key> -t <tox_file>\n");
	fprintf(stderr, "                                                  Add a friend and exit\n");
	fprintf(stderr, "       toxtun -d <tox_address>|<public_key> -t <tox_file>\n");
	fprintf(stderr, "                                                  Delete a friend and exit\n");
	fprintf(stderr, "       toxtun -c <friend_number> -t <tox_file> [options]\n");
	fprintf(stderr, "                                                  Start the tunnel\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "	-t, --file          Tox file\n");
	fprintf(stderr, "	-n, --new           Create new tox file and exit\n");
	fprintf(stderr, "	-f, --friend        Add a friend to the tox file and exit\n");
	fprintf(stderr, "	-d, --delete        Delete a friend from the tox file and exit\n");
	fprintf(stderr, "	-h, --help          Show this help and exit\n");

	fprintf(stderr, "	-c, --connect       Friend number to tunnel with (starts the tunnel)\n");
	fprintf(stderr, "	-i, --interface     TUN interface name (default: toxtun0)\n");
	fprintf(stderr, "	-l, --lossy         Send packets as Tox lossy instead of lossless\n");
}

static bool parse_pubkey(uint8_t* pubkey, const char* str, int str_len)
{
	if (str_len != TOX_ADDRESS_SIZE * 2 && str_len != TOX_PUBLIC_KEY_SIZE * 2)
	{
		return false;
	}

	return sodium_hex2bin(pubkey, TOX_PUBLIC_KEY_SIZE, str, TOX_PUBLIC_KEY_SIZE * 2, NULL, NULL, NULL) == 0;
}

static struct app_data* create_app_data(int argc, char *argv[])
{
	static struct option long_opts[] = {
		{"file", required_argument, 0, 't'},
		{"tox", required_argument, 0, 't'},
		{"new", no_argument, 0, 'n'},
		{"friend", required_argument, 0, 'f'},
		{"delete", required_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{"interface", required_argument, 0, 'i'},
		{"connect", required_argument, 0, 'c'},
		{"lossy", no_argument, 0, 'l'},
		{NULL, no_argument, NULL, 0},
	};

	const char *opts_str = "t:nf:d:hi:c:l";
	int opt, indexptr;

	struct app_data* app = (struct app_data*)malloc(sizeof(struct app_data));
	memset(app, 0, sizeof(struct app_data));

	snprintf(app->tun_name, sizeof(app->tun_name), "toxtun0");
	app->friend_number = 0;
	app->tun_fd = -1;

	while ((opt = getopt_long(argc, argv, opts_str, long_opts, &indexptr)) != -1)
	{
		int optarg_len = optarg ? strlen(optarg) : 0;
		switch (opt)
		{
			case 'n':
				app->create = 1;
				break;

			case 't':
				snprintf(app->tox_file, sizeof(app->tox_file), "%s", optarg);
				break;

			case 'f':
				if (!parse_pubkey(app->friend_pubkey, optarg, optarg_len))
				{
					fprintf(stderr, "Valid tox address or public key required\n");
					free(app);
					return NULL;
				}
				app->add_friend = 1;
				break;

			case 'd':
				if (!parse_pubkey(app->friend_pubkey, optarg, optarg_len))
				{
					fprintf(stderr, "Valid tox address or public key required\n");
					free(app);
					return NULL;
				}
				app->del_friend = 1;
				break;

			case 'i':
				snprintf(app->tun_name, sizeof(app->tun_name), "%s", optarg);
				break;

			case 'c':
				app->friend_number = (uint32_t)atoi(optarg);
				app->connect = 1;
				break;

			case 'l':
				app->use_lossy = 1;
				break;

			case 'h':
				app->usage_only = 1;
				print_usage();
				return app;

			default:
				print_usage();
				free(app);
				return NULL;
		}
	}

	return app;
}

typedef struct DHT_node {
	const char *ip;
	uint16_t port;
	const char key_hex[TOX_PUBLIC_KEY_SIZE*2 + 1];
	unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;

static bool create_tox(struct app_data* app)
{
	Tox_Err_Options_New options_err;
	struct Tox_Options* options = NULL;
	char* savedata = NULL;
	long fsize = 0;
	bool result = false;

	FILE *f = fopen(app->tox_file, "rb");
	if (f)
	{
		if (app->create)
		{
			fprintf(stderr, "File already exists\n");
			fclose(f);
			return false;
		}

		fseek(f, 0, SEEK_END);
		fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		if (fsize <= 0 || (savedata = (char*)malloc(fsize)) == NULL || fread(savedata, fsize, 1, f) != 1)
		{
			fprintf(stderr, "Invalid tox file\n");
			fclose(f);
			free(savedata);
			return false;
		}

		fclose(f);
	}
	else if (!app->create)
	{
		fprintf(stderr, "Invalid tox file\n");
		return false;
	}

	options = tox_options_new(&options_err);
	if (options == NULL)
	{
		fprintf(stderr, "Unable to create tox options (%d)\n", options_err);
		free(savedata);
		return false;
	}

	if (savedata)
	{
		tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
		tox_options_set_savedata_data(options, (const uint8_t*)savedata, fsize);
	}

	{
		Tox_Err_New new_err;
		app->tox = tox_new(options, &new_err);
		if (app->tox)
		{
			result = true;
		}
		else
		{
			fprintf(stderr, "Unable to create tox instance (%d)\n", new_err);
		}
	}

	tox_options_free(options);
	free(savedata);

	return result;
}

static void update_savedata_file(struct app_data* app)
{
	size_t size = tox_get_savedata_size(app->tox);
	char* savedata = (char*)malloc(size);
	tox_get_savedata(app->tox, (uint8_t*)savedata);

	FILE *f = fopen(app->tox_file, "wb");
	fwrite(savedata, size, 1, f);
	fclose(f);

	free(savedata);
}

static void bootstrap(Tox *tox)
{
	DHT_node nodes[] =
	{
		{"144.217.167.73", 33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
		{"172.104.215.182", 33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
		{"188.245.84.166", 33445, "96B66D300BA2B59B98FC42DB1325E7092388F0379593E680ABDBEA03B9C9CE03", {0}},
		{"198.199.98.108", 33445, "BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F", {0}},
		{"tox.initramfs.io", 33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
		{"node.toxbootstrap.org", 33445, "451C6B9B11DAF61336D8C5892BB00210EEFF3E9C58BE1827BFD442C163155B79", {0}}
	};

	for (size_t i = 0; i < sizeof(nodes)/sizeof(DHT_node); i ++)
	{
		sodium_hex2bin(nodes[i].key_bin, sizeof(nodes[i].key_bin),
					nodes[i].key_hex, sizeof(nodes[i].key_hex)-1, NULL, NULL, NULL);
		tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, NULL);
		tox_add_tcp_relay(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, NULL);
	}
}

static void print_tox_id(Tox *tox)
{
	uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
	tox_self_get_address(tox, tox_id_bin);

	char tox_id_hex[TOX_ADDRESS_SIZE*2 + 1];
	sodium_bin2hex(tox_id_hex, sizeof(tox_id_hex), tox_id_bin, sizeof(tox_id_bin));

	for (size_t i = 0; i < sizeof(tox_id_hex)-1; i ++)
	{
		tox_id_hex[i] = toupper(tox_id_hex[i]);
	}

	printf("Tox ID: %s\n", tox_id_hex);
}

static void self_connection_status_cb(Tox* tox, TOX_CONNECTION connection_status, void* user_data)
{
	switch (connection_status)
	{
		case TOX_CONNECTION_NONE:
			printf("Offline\n");
			break;
		case TOX_CONNECTION_TCP:
			printf("Online, using TCP\n");
			break;
		case TOX_CONNECTION_UDP:
			printf("Online, using UDP\n");
			break;
	}
}

static void friend_connection_status_cb(Tox* tox, uint32_t friend_number, TOX_CONNECTION connection_status, void* user_data)
{
	switch (connection_status)
	{
		case TOX_CONNECTION_NONE:
			printf("Friend %d: Offline\n", friend_number);
			break;
		case TOX_CONNECTION_TCP:
			printf("Friend %d: Online, using TCP\n", friend_number);
			break;
		case TOX_CONNECTION_UDP:
			printf("Friend %d: Online, using UDP\n", friend_number);
			break;
	}
}

static int open_tun(struct app_data* app)
{
	int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	if (fd < 0)
	{
		perror("open /dev/net/tun");
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (app->tun_name[0])
	{
		strncpy(ifr.ifr_name, app->tun_name, IFNAMSIZ - 1);
	}

	if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0)
	{
		perror("ioctl TUNSETIFF");
		close(fd);
		return -1;
	}

	strncpy(app->tun_name, ifr.ifr_name, IFNAMSIZ - 1);
	app->tun_name[IFNAMSIZ - 1] = '\0';

	return fd;
}

static int write_tun(struct app_data* app, const uint8_t* data, size_t length)
{
	size_t pos = 0;
	while (pos < length)
	{
		ssize_t n = write(app->tun_fd, data + pos, length - pos);
		if (n < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				return (int)pos;
			}
			perror("write tun");
			return -1;
		}
		pos += (size_t)n;
	}
	return (int)pos;
}

static int send_tun_packet(struct app_data* app, const uint8_t* data, size_t length)
{
	if (length == 0 || length >= TOX_MAX_CUSTOM_PACKET_SIZE)
	{
		return 0;
	}

	uint8_t packet[TOX_MAX_CUSTOM_PACKET_SIZE];
	packet[0] = app->use_lossy ? PACKET_PREFIX_LOSSY : PACKET_PREFIX_LOSSLESS;
	memcpy(packet + 1, data, length);

	uint32_t peer = app->friend_number;

	TOX_ERR_FRIEND_CUSTOM_PACKET err;
	bool sent;
	if (app->use_lossy)
	{
		sent = tox_friend_send_lossy_packet(app->tox, peer, packet, length + 1, &err);
	}
	else
	{
		sent = tox_friend_send_lossless_packet(app->tox, peer, packet, length + 1, &err);
	}

	if (!sent || err != TOX_ERR_FRIEND_CUSTOM_PACKET_OK)
	{
		fprintf(stderr, "Failed to send tun packet to friend %u (%d)\n", peer, err);
		return 0;
	}

	app->last_tox_activity_time = monotonic_now_us();
	return 1;
}

static int handle_tun_readable(struct app_data* app)
{
	ssize_t n = read(app->tun_fd, app->tun_buf, sizeof(app->tun_buf));
	if (n > 0)
	{
		if (n >= TOX_MAX_CUSTOM_PACKET_SIZE)
		{
			fprintf(stderr, "TUN packet too large: %zd\n", n);
		}
		else if (!send_tun_packet(app, app->tun_buf, (size_t)n))
		{
			fprintf(stderr, "Dropped TUN packet\n");
		}

		return 0;
	}

	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
	{
		perror("read tun");
		return -1;
	}

	return 0;
}

static void friend_packet_cb(Tox* tox, uint32_t friend_number, const uint8_t* data, size_t length, void* user_data)
{
	struct app_data* app = (struct app_data*)user_data;

	if (friend_number != app->friend_number)
	{
		return;
	}

	app->last_tox_activity_time = monotonic_now_us();

	if (length < 2 || (data[0] != PACKET_PREFIX_LOSSLESS && data[0] != PACKET_PREFIX_LOSSY))
	{
		return;
	}

	write_tun(app, data + 1, length - 1);
}

static uint32_t tox_poll_timeout_ms(struct app_data* app)
{
	if (monotonic_now_us() - app->last_tox_activity_time > STANDBY_TIMEOUT_US)
	{
		return tox_iteration_interval(app->tox);
	}

	return 1;
}

static int run_event_loop(struct app_data* app)
{
	while (!quit_requested)
	{
		struct pollfd pfd = {
			.fd = app->tun_fd,
			.events = POLLIN,
			.revents = 0
		};

		int rc = poll(&pfd, 1, (int)tox_poll_timeout_ms(app));
		if (rc < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}

			perror("poll tun");
			return -1;
		}

		if (rc > 0)
		{
			if (pfd.revents & POLLIN)
			{
				if (handle_tun_readable(app) < 0)
				{
					return -1;
				}
			}

			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			{
				fprintf(stderr, "TUN descriptor failed\n");
				return -1;
			}
		}

		tox_iterate(app->tox, app);
	}

	return 0;
}

int main(int argc, char* argv[])
{
	setvbuf(stdout, NULL, _IOLBF, 0);

	int res = 0;
	uint32_t* friend_list = NULL;
	size_t friend_count = 0;

	struct app_data* app = create_app_data(argc, argv);
	if (!app)
	{
		return -1;
	}

	if (app->usage_only)
	{
		return 0;
	}

	if (app->tox_file[0] == 0)
	{
		print_usage();
		free(app);
		return -1;
	}

	if (!create_tox(app))
	{
		free(app);
		return -1;
	}

	if (app->add_friend)
	{
		tox_friend_add_norequest(app->tox, app->friend_pubkey, NULL);
	}

	if (app->del_friend)
	{
		TOX_ERR_FRIEND_BY_PUBLIC_KEY error;
		uint32_t friend_number = tox_friend_by_public_key(app->tox, app->friend_pubkey, &error);
		if (friend_number == UINT32_MAX)
		{
			fprintf(stderr, "No friend with the specified public key found\n");
			res = -1;
			goto cleanup;
		}

		tox_friend_delete(app->tox, friend_number, NULL);
	}

	print_tox_id(app->tox);

	friend_count = tox_self_get_friend_list_size(app->tox);
	if (friend_count)
	{
		friend_list = (uint32_t*)malloc(friend_count * sizeof(uint32_t));
		tox_self_get_friend_list(app->tox, friend_list);

		printf("Friend list:\n");
		for (size_t i = 0; i < friend_count; i++)
		{
			uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
			TOX_ERR_FRIEND_GET_PUBLIC_KEY error;
			if (tox_friend_get_public_key(app->tox, friend_list[i], public_key, &error))
			{
				char public_key_hex[TOX_PUBLIC_KEY_SIZE * 2 + 1];
				sodium_bin2hex(public_key_hex, sizeof(public_key_hex), public_key, sizeof(public_key));

				for (size_t j = 0; j < sizeof(public_key_hex) - 1; j++)
				{
					public_key_hex[j] = toupper(public_key_hex[j]);
				}

				printf("	%d:\t%s\n", friend_list[i], public_key_hex);
			}
		}
	}

	if (app->create || app->add_friend || app->del_friend)
	{
		update_savedata_file(app);
		goto cleanup;
	}

	if (!app->connect)
	{
		goto cleanup;
	}

	tox_callback_friend_lossless_packet(app->tox, friend_packet_cb);
	tox_callback_friend_lossy_packet(app->tox, friend_packet_cb);
	tox_callback_self_connection_status(app->tox, self_connection_status_cb);
	tox_callback_friend_connection_status(app->tox, friend_connection_status_cb);

	bootstrap(app->tox);

	const char *name = "Tox TUN";
	tox_self_set_name(app->tox, (const uint8_t*)name, strlen(name), NULL);

	const char *status_message = "Tunneling IP packets over Tox";
	tox_self_set_status_message(app->tox, (const uint8_t*)status_message, strlen(status_message), NULL);

	setlocale(LC_ALL, "en-US");

	app->tun_fd = open_tun(app);
	if (app->tun_fd < 0)
	{
		res = -1;
		goto cleanup;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	printf("TUN interface: %s\n", app->tun_name);
	printf("Tunneling with friend %u\n", app->friend_number);

	app->last_tox_activity_time = monotonic_now_us();
	tox_iterate(app->tox, app);

	if (run_event_loop(app) < 0)
	{
		res = -1;
	}

	printf("Quitting...\n");

cleanup:
	if (app->tun_fd >= 0)
	{
		close(app->tun_fd);
		app->tun_fd = -1;
	}

	if (app->tox)
	{
		tox_kill(app->tox);
	}

	free(friend_list);
	free(app);

	return res;
}
