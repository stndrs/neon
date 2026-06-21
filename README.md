# neon

[![Package Version](https://img.shields.io/hexpm/v/neon)](https://hex.pm/packages/neon)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/neon/)

A networking library for Gleam on the Erlang target. Provides TCP, UDP, and SSL/TLS sockets with a builder-style API, support for both active and passive modes, IPv4 and IPv6, and START-TLS upgrades. Built on Erlang's `gen_tcp`, `gen_udp`, and `ssl` modules.

```sh
gleam add neon@3
```

### TCP

```gleam
import neon/net
import neon/tcp

pub fn main() {
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)
  let assert Ok(listener) = tcp.listen(port, loopback)
  let assert Ok(port) = tcp.port(listener)

  let address = net.ip_address(loopback)
  let assert Ok(socket) =
    tcp.new(address, port)
    |> tcp.connect

  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(server) = tcp.accept(listener, timeout)
  let assert Ok(Nil) = tcp.send(server, <<"hello world":utf8>>)

  let assert Ok(msg) = tcp.receive(socket, 11, timeout)
  let assert <<"hello world":utf8>> = msg
}
```

### SSL/TLS

```gleam
import neon/net
import neon/ssl

pub fn main() {
  let assert Ok(Nil) = ssl.start()

  // Connect to a TLS server with certificate verification
  let assert Ok(port) = net.port(443)
  let assert Ok(socket) =
    ssl.new(net.hostname("gleam.run"), port)
    |> ssl.connect

  let assert Ok(Nil) =
    ssl.send(socket, <<"GET / HTTP/1.0\r\nHost: gleam.run\r\n\r\n":utf8>>)

  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(response) = ssl.receive(socket, 0, timeout)
}
```

### Mutual TLS (mTLS)

In mutual TLS the client authenticates itself with a certificate and the server
verifies it against a trusted CA. Certificates and private keys are DER-encoded
binaries.

On the **client**, present a certificate with `connect_cert`:

```gleam
import neon/net
import neon/ssl

pub fn main() {
  let assert Ok(Nil) = ssl.start()

  // DER-encoded client certificate and private key (e.g. loaded from disk)
  let client_cert: BitArray = todo
  let client_key = ssl.rsa_private_key(todo)

  let assert Ok(port) = net.port(8443)
  let assert Ok(socket) =
    ssl.new(net.hostname("example.com"), port)
    |> ssl.connect_cert(client_cert, key: client_key)
    |> ssl.connect

  let assert Ok(Nil) = ssl.send(socket, <<"hello":utf8>>)
}
```

On the **server**, require and verify client certificates with
`handshake_cacerts`. This enables `verify_peer` with `fail_if_no_peer_cert`, so
a client that does not present a valid, CA-signed certificate is rejected during
the handshake:

```gleam
import neon/net
import neon/ssl

pub fn main() {
  let assert Ok(Nil) = ssl.start()

  // DER-encoded server certificate/key, plus the CA certificate(s) to trust
  let server_cert: BitArray = todo
  let server_key = ssl.rsa_private_key(todo)
  let trusted_cacerts: List(BitArray) = todo

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(8443)
  let assert Ok(listener) = ssl.listen(port, loopback)

  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(transport) = ssl.accept(listener, timeout)

  let opts =
    ssl.handshake_options(server_cert, key: server_key)
    |> ssl.handshake_cacerts(trusted_cacerts)
  let assert Ok(socket) = ssl.handshake(transport, opts)

  let assert Ok(msg) = ssl.receive(socket, 0, timeout)
}
```

### UDP

```gleam
import neon/net
import neon/udp

pub fn main() {
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let address = net.ip_address(loopback)

  // Open two sockets on OS-assigned ports
  let assert Ok(port) = net.port(0)
  let assert Ok(socket_a) =
    udp.new(port)
    |> udp.ip_address(loopback)
    |> udp.open
  let assert Ok(socket_b) =
    udp.new(port)
    |> udp.ip_address(loopback)
    |> udp.open

  // Connect socket_a to socket_b's address
  let assert Ok(port_b) = udp.port(socket_b)
  let assert Ok(Nil) = udp.connect(socket_a, address, port_b)

  // Send from A, receive on B
  let assert Ok(Nil) = udp.send(socket_a, <<"hello":utf8>>)
  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(msg) = udp.receive(socket_b, 0, timeout)
  let assert <<"hello":utf8>> = msg.payload
}
```

Further documentation can be found at <https://hexdocs.pm/neon>.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```
