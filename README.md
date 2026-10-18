# toxtun

Tunnel IP traffic through the Tox peer-to-peer messaging protocol using a TUN interface.

## Dependencies

- [toxcore](https://github.com/TokTok/c-toxcore) (libtoxcore)
- [libsodium](https://github.com/jedisct1/libsodium)
- Linux TUN support (/dev/net/tun)

## Build

```sh
gcc -Wall -Wextra $(pkg-config --cflags toxcore libsodium) \
    main.c -o toxtun \
    $(pkg-config --libs toxcore libsodium)
```

## Usage

### Show profile and friends

With only `-t`, the daemon prints the Tox ID and friend list (with their local
friend numbers) and exits:

```sh
./toxtun -t client.tox
```

### Create a new Tox profile

```sh
./toxtun -n -t myprofile.tox
```

### Add a friend

```sh
./toxtun -f <tox_address_or_public_key> -t myprofile.tox
```

### Delete a friend

```sh
./toxtun -d <tox_address_or_public_key> -t myprofile.tox
```

There is no client/server distinction: both endpoints run the same daemon.

### TUN interface (created manually, not by this daemon)

The daemon never creates or configures interfaces. Create the interface as root,
assign ownership to the daemon user, and configure its address and MTU:

```sh
sudo ip tuntap add dev toxtun0 mode tun user $(id -un)
sudo ip link set dev toxtun0 mtu 1200
sudo ip addr add 10.0.0.2/24 dev toxtun0
sudo ip link set dev toxtun0 up
```

Give the other endpoint a different address in the same subnet, for example `10.0.0.3/24`.

Depending on the distribution, the daemon user may also need read/write access to
`/dev/net/tun`.

### Start the tunnel

The tunnel only starts when `-c <friend_number>` is given:

```sh
./toxtun -c 0 -t client.tox -i toxtun0
```

The tunnel is pinned to the local friend number given with `-c`. Packets from
and to any other friend are ignored. Friend numbers are local to each Tox
profile; run with only `-t` to list them.

Friends must be added explicitly with `-f`; incoming friend requests are ignored.

### Custom interface or friend

```sh
./toxtun -c 1 -t client.tox -i toxtun0
```

Use the same manual interface MTU on both endpoints. The maximum is 1372 bytes:
the Tox custom-packet limit is 1373 bytes, minus 1 byte for the tunnel prefix.
Larger packets are dropped and logged.

### Lossy mode

By default packets are sent as Tox **lossless** custom packets, which is what
works reliably. To send them as **lossy** packets instead (lower latency, but
delivery is best-effort):

```sh
./toxtun -c 0 -t client.tox -i toxtun0 -l
```

Either endpoint may pick its own mode; the receive path accepts packets prefixed
with either marker, so a lossy and a lossless endpoint can talk to each other.

| Mode               | Flag | Prefix byte  | Constant                 |
|--------------------|------|--------------|--------------------------|
| Lossless (default) |      | 160 (`0xA0`) | `PACKET_PREFIX_LOSSLESS` |
| Lossy              | `-l` | 200 (`0xC8`) | `PACKET_PREFIX_LOSSY`    |

The lossy prefix is 200, not 192, because toxcore reserves lossy packet IDs
192-199 (`0xC0`-`0xC7`) for AV/RTP and silently swallows them.

## How it works

- The daemon attaches to an existing TUN interface using `TUNSETIFF`.
- IP packets read from the TUN interface are sent as Tox custom packets with a
  one-byte prefix: 160 (`0xA0`) for lossless (default) or 200 (`0xC8`) for lossy (`-l`).
- Received packets have their prefix stripped and are written back to the TUN interface.
- IP reliability is left to the protocols running inside the tunnel, such as TCP or QUIC.
