import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/erlang/process
import gleam/result
import neon/net
import neon/ssl.{type Ssl}
import neon/tcp
import neon/testing

const host = "localhost"

const loopback_str = "127.0.0.1"

// ---------- upgrade ---------- //

pub fn upgrade_test() {
  let test_subject = process.new_subject()

  use ip_address <- with_ipv4_address()
  use tcp_listener <- with_tcp_listener(ip_address)
  use _data <- with_ssl_server_upgrade(tcp_listener.socket, test_subject)

  use address <- with_loopback()

  let assert Ok(client_tcp) =
    address
    |> tcp.new(tcp_listener.port)
    |> tcp.connect

  let host = net.hostname(host)

  // Client-side upgrade
  let assert Ok(_ssl_socket) =
    ssl.from_tcp(client_tcp, host)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn upgrade_ip_address_test() {
  let test_subject = process.new_subject()

  use ip_address <- with_ipv4_address()
  use listener <- with_tcp_listener(ip_address)
  use _data <- with_ssl_server_upgrade(listener.socket, test_subject)
  use loopback <- with_loopback()

  let assert Ok(client_tcp) =
    loopback
    |> tcp.new(listener.port)
    |> tcp.connect

  // Client-side upgrade
  let assert Ok(_ssl_socket) =
    ssl.from_tcp(client_tcp, listener.address)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn upgrade_ip_address_verify_peer_test() {
  let test_subject = process.new_subject()

  use ip_address <- with_ipv4_address()
  use tcp_listener <- with_tcp_listener(ip_address)
  use data <- with_ssl_server_upgrade(tcp_listener.socket, test_subject)
  use loopback <- with_loopback()

  let assert Ok(client_tcp) =
    loopback
    |> tcp.new(tcp_listener.port)
    |> tcp.connect

  let host = net.hostname(host)

  // Client-side upgrade
  let assert Ok(_ssl_socket) =
    ssl.from_tcp(client_tcp, host)
    |> ssl.verify_peer
    |> ssl.connect_cacerts(data.server.cacerts)
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn upgrade_error_test() {
  use ip_address <- with_ipv4_address()
  use tcp_listener <- with_tcp_listener(ip_address)

  let test_subject = process.new_subject()
  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(accepted) = tcp.accept(tcp_listener.socket, timeout)

      let _ = tcp.close(accepted)
      process.send(test_subject, Nil)
    })

  use loopback <- with_loopback()

  let assert Ok(socket) =
    loopback
    |> tcp.new(tcp_listener.port)
    |> tcp.connect

  let host = net.hostname(host)

  assert Error(ssl.Closed)
    == ssl.from_tcp(socket, host)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

// ---------- connect ---------- //

pub fn connect_test() {
  let test_subject = process.new_subject()

  use ip_address <- with_ipv4_address()
  use listener <- with_ssl_listener(ip_address)
  use _data <- with_ssl_server(listener.socket, test_subject)

  let host = net.hostname(host)

  let assert Ok(_ssl_socket) =
    ssl.new(host, listener.port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn connect_to_ip_address_test() {
  let test_subject = process.new_subject()

  use ip_address <- with_ipv4_address()
  use listener <- with_ssl_listener(ip_address)
  use _data <- with_ssl_server(listener.socket, test_subject)

  let assert Ok(_ssl_socket) =
    ssl.new(listener.address, listener.port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn connect_ipv6_test() {
  let test_subject = process.new_subject()

  use ip_address <- with_ipv6_address()
  use listener <- with_ssl_listener(ip_address)
  use _data <- with_ssl_server(listener.socket, test_subject)

  let ip_address = net.ip_address(ip_address)

  let assert Ok(_ssl_socket) =
    ssl.new(ip_address, listener.port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn connect_verify_peer_test() {
  use ip_address <- with_ipv4_address()
  use listener <- with_tcp_listener(ip_address)
  use data <- with_ssl_server_upgrade(listener.socket, process.new_subject())

  let assert Ok(address) =
    net.parse_ip_address(loopback_str)
    |> result.map(net.ip_address)

  let assert Ok(client_tcp) =
    address
    |> tcp.new(listener.port)
    |> tcp.connect

  let host = net.hostname(host)

  let assert Ok(_ssl_socket) =
    ssl.from_tcp(client_tcp, host)
    |> ssl.verify_peer
    |> ssl.connect_cacerts(data.server.cacerts)
    |> ssl.connect
}

pub fn connect_ip_address_verify_peer_test() {
  use ip_address <- with_ipv4_address()
  use listener <- with_tcp_listener(ip_address)
  use data <- with_ssl_server_upgrade(listener.socket, process.new_subject())

  use loopback <- with_loopback()

  let assert Ok(client_tcp) =
    loopback
    |> tcp.new(listener.port)
    |> tcp.connect

  let assert Ok(_ssl_socket) =
    ssl.from_tcp(client_tcp, listener.address)
    |> ssl.verify_peer
    |> ssl.connect_cacerts(data.server.cacerts)
    |> ssl.connect
}

pub fn connect_timeout_test() {
  // Listen but never accept
  use ip_address <- with_ipv4_address()
  use tcp_listener <- with_tcp_listener(ip_address)

  let assert Ok(short_timeout) = net.timeout(50)

  let host = net.hostname(host)

  assert Error(ssl.Timeout)
    == ssl.new(host, tcp_listener.port)
    |> ssl.verify_none
    |> ssl.timeout(short_timeout)
    |> ssl.connect

  tcp.close(tcp_listener.socket)
}

pub fn connect_error_test() {
  let assert Ok(port) = net.port(1)

  let host = net.hostname(host)

  assert Error(ssl.Posix(net.Econnrefused))
    == ssl.new(host, port)
    |> ssl.connect
}

pub fn connect_tls_alert_unknown_ca_test() {
  let server_data = testing.pkix_test_data(testing.rsa(2048), host)
  let wrong_ca_data = testing.pkix_test_data(testing.rsa(2048), host)

  use ip_address <- with_ipv4_address()
  use listener <- with_ssl_listener(ip_address)

  let hs_opts =
    ssl.handshake_options(server_data.server.cert, server_data.server.key)

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener.socket, timeout)
      use <- with_suppressed_logging()

      let _result = ssl.handshake(transport, hs_opts)
    })

  let host = net.hostname(host)

  // The client trusts the wrong CA and should get UnknownCa alert
  let assert Error(ssl.TlsAlert(ssl.UnknownCa, _description)) =
    ssl.new(host, listener.port)
    |> ssl.verify_peer
    |> ssl.connect_cacerts(wrong_ca_data.client.cacerts)
    |> ssl.connect
}

pub fn connect_ip_address_verify_peer_direct_test() {
  let test_subject = process.new_subject()

  use ip_address <- with_ipv4_address()
  use listener <- with_ssl_listener(ip_address)
  use data <- with_ssl_server(listener.socket, test_subject)

  // verify_peer with IP address (SNI disabled, no hostname check)
  let assert Ok(_ssl_socket) =
    ssl.new(listener.address, listener.port)
    |> ssl.verify_peer
    |> ssl.connect_cacerts(data.server.cacerts)
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn connect_wrong_cacerts_test() {
  let server_data = testing.pkix_test_data(testing.rsa(2048), host)
  let wrong_data = testing.pkix_test_data(testing.rsa(2048), host)

  use ip_address <- with_ipv4_address()
  use listener <- with_ssl_listener(ip_address)

  let hs_opts =
    ssl.handshake_options(server_data.server.cert, server_data.server.key)

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener.socket, timeout)
      use <- with_suppressed_logging()

      let _result = ssl.handshake(transport, hs_opts)
    })

  // Client uses wrong CA certs — should fail
  let assert Error(ssl.TlsAlert(ssl.UnknownCa, _)) =
    ssl.new(listener.address, listener.port)
    |> ssl.verify_peer
    |> ssl.connect_cacerts(wrong_data.client.cacerts)
    |> ssl.connect
}

// ---------- send ---------- //

pub fn send_test() {
  use #(ssl_socket, _server_ssl) <- with_connected_pair()

  assert Ok(Nil) == ssl.send(ssl_socket, <<"hello ssl":utf8>>)
  assert Ok(Nil) == ssl.shutdown(ssl_socket)
}

pub fn send_large_payload_test() {
  use #(client, server) <- with_connected_pair()

  // 100KB payload — larger than a single TLS record (16KB max)
  let payload = crypto.strong_random_bytes(100_000)

  assert Ok(Nil) == ssl.send(client, payload)

  // Receive in a loop since data may arrive in chunks
  let assert Ok(received) = receive_all(server, 100_000)
  assert received == payload
}

pub fn send_closed_test() {
  use #(ssl_socket, _server_ssl) <- with_connected_pair()

  let assert Ok(_) = ssl.shutdown(ssl_socket)
  process.sleep(50)
  assert Error(ssl.Closed) == ssl.send(ssl_socket, <<"hello":utf8>>)
}

// ---------- receive ---------- //

pub fn receive_test() {
  use #(ssl_socket, server_ssl) <- with_connected_pair()

  // Server sends data over SSL
  let assert Ok(_) = ssl.send(server_ssl, <<"hello ssl":utf8>>)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"hello ssl":utf8>>) = ssl.receive(ssl_socket, 9, timeout)
}

pub fn receive_timeout_test() {
  use #(ssl_socket, server_ssl) <- with_connected_pair()

  // No data is sent, so receive should time out
  let assert Ok(timeout) = net.timeout(100)
  assert Error(ssl.Timeout) == ssl.receive(ssl_socket, 1, timeout)

  let _ = ssl.close(server_ssl)
}

pub fn receive_forever_test() {
  use #(ssl_socket, server_ssl) <- with_connected_pair()
  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(_) = ssl.send(server_ssl, <<"world ssl":utf8>>)
      process.send(test_subject, Nil)
    })

  let assert Ok(<<"world ssl":utf8>>) = ssl.receive(ssl_socket, 9, net.infinity)

  let assert Ok(_) = process.receive(test_subject, 1000)
}

pub fn receive_negative_length_test() {
  use #(ssl_socket, _server_ssl) <- with_connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  assert Error(ssl.SslError("Length must be non-negative"))
    == ssl.receive(ssl_socket, -1, timeout)
}

pub fn receive_closed_test() {
  use #(ssl_socket, server_ssl) <- with_connected_pair()

  assert Ok(Nil) == ssl.close(server_ssl)

  process.sleep(50)

  let assert Ok(timeout) = net.timeout(1000)
  assert Error(ssl.Closed) == ssl.receive(ssl_socket, 1, timeout)
}

pub fn receive_forever_closed_test() {
  use #(ssl_socket, server_ssl) <- with_connected_pair()
  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      assert Ok(Nil) == ssl.close(server_ssl)
      process.send(test_subject, Nil)
    })

  assert Error(ssl.Closed) == ssl.receive(ssl_socket, 1, net.infinity)

  let assert Ok(_) = process.receive(test_subject, 1000)
}

// ---------- close ---------- //

pub fn close_test() {
  use #(ssl_socket, server_ssl) <- with_connected_pair()

  assert Ok(Nil) == ssl.close(ssl_socket)
  assert Ok(Nil) == ssl.close(ssl_socket)

  assert Ok(Nil) == ssl.close(server_ssl)
  assert Ok(Nil) == ssl.close(server_ssl)
}

// ---------- shutdown ---------- //

pub fn shutdown_test() {
  use #(ssl_socket, _server_ssl) <- with_connected_pair()

  assert Ok(Nil) == ssl.shutdown(ssl_socket)
}

pub fn shutdown_closed_test() {
  use #(ssl_socket, server_ssl) <- with_connected_pair()

  assert Ok(Nil) == ssl.close(server_ssl)

  process.sleep(50)

  assert Error(ssl.Closed) == ssl.shutdown(ssl_socket)
}

// ---------- active ---------- //

pub fn active_test() {
  use #(client, server) <- with_connected_pair()

  // Put client into active mode
  let assert Ok(_) = ssl.active(client)

  // Server sends data
  assert Ok(Nil) == ssl.send(server, <<"hello active":utf8>>)

  // Client receives data as an SslMessage via selector
  let selector =
    process.new_selector()
    |> ssl.select(fn(msg) { msg })

  let assert Ok(ssl.Packet(_, <<"hello active":utf8>>)) =
    process.selector_receive(from: selector, within: 1000)
}

pub fn active_closed_test() {
  use #(client, server) <- with_connected_pair()

  // Put client into active mode
  let assert Ok(_) = ssl.active(client)

  // Server closes its side
  assert Ok(Nil) == ssl.close(server)

  // Client receives SocketClosed message
  let selector =
    process.new_selector()
    |> ssl.select(fn(msg) { msg })

  let assert Ok(ssl.SocketClosed(_)) =
    process.selector_receive(from: selector, within: 1000)
}

pub fn passive_test() {
  use #(client, server) <- with_connected_pair()

  // Put client into active mode, then immediately back to passive
  let assert Ok(client) = ssl.active(client)
  let assert Ok(_) = ssl.passive(client)

  // Server sends data
  assert Ok(Nil) == ssl.send(server, <<"passive data":utf8>>)

  // Give data time to arrive at the socket
  process.sleep(50)

  // No message should be delivered since socket is passive
  let selector =
    process.new_selector()
    |> ssl.select(fn(msg) { msg })

  assert Error(Nil) == process.selector_receive(from: selector, within: 100)

  // But synchronous receive should work
  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"passive data":utf8>>) = ssl.receive(client, 0, timeout)
}

pub fn active_then_passive_test() {
  use #(client, server) <- with_connected_pair()

  // Put client into active mode
  let assert Ok(client) = ssl.active(client)

  // Server sends first message
  assert Ok(Nil) == ssl.send(server, <<"first":utf8>>)

  // Client receives first message via selector
  let selector =
    process.new_selector()
    |> ssl.select(fn(msg) { msg })

  let assert Ok(ssl.Packet(_, <<"first":utf8>>)) =
    process.selector_receive(from: selector, within: 1000)

  // Switch to passive
  let assert Ok(_) = ssl.passive(client)

  // Server sends second message
  assert Ok(Nil) == ssl.send(server, <<"second":utf8>>)

  // Give data time to arrive
  process.sleep(50)

  // Client receives second message synchronously
  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"second":utf8>>) = ssl.receive(client, 0, timeout)
}

pub fn controlling_process_test() {
  use #(client, server) <- with_connected_pair()

  // Switch to active mode
  let assert Ok(client) = ssl.active(client)

  // Create a process for receiving a message
  let pid =
    process.spawn(fn() {
      let selector = process.new_selector()

      assert process.selector_receive_forever(from: selector)
        == ssl.Packet(client, <<"foo!":utf8>>)
    })

  assert ssl.controlling_process(client, pid) == Ok(Nil)

  assert Ok(Nil) == ssl.send(server, <<"foo!":utf8>>)
}

pub fn controlling_process_close_test() {
  use #(client, _server) <- with_connected_pair()

  // Closes the socket on server side
  assert ssl.close(client) == Ok(Nil)

  assert ssl.controlling_process(client, process.self()) == Error(ssl.Closed)
}

pub fn controlling_process_invalid_pid_test() {
  use #(client, _server) <- with_connected_pair()

  // Spawn a process that immediately exits
  let pid = process.spawn(fn() { Nil })
  process.sleep(10)

  assert ssl.controlling_process(client, pid) == Error(ssl.InvalidPid)
}

// ---------- port ---------- //

pub fn port_test() {
  use #(client_ssl, server_ssl) <- with_connected_pair()

  let assert Ok(client_port) = ssl.port(client_ssl)
  assert net.port_to_int(client_port) > 0

  let assert Ok(server_port) = ssl.port(server_ssl)
  assert net.port_to_int(server_port) > 0
}

pub fn port_closed_test() {
  use #(ssl_socket, _server_ssl) <- with_connected_pair()

  assert Ok(Nil) == ssl.close(ssl_socket)

  let assert Error(ssl.Posix(_posix)) = ssl.port(ssl_socket)
}

// ---------- server: listen ---------- //

pub fn listen_test() {
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  assert net.port_to_int(listener_port) > 0
}

// ---------- server: accept ---------- //

pub fn accept_timeout_test() {
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)

  let assert Ok(timeout) = net.timeout(100)
  assert Error(ssl.Timeout) == ssl.accept(listener, timeout)
}

pub fn accept_non_listener_test() {
  use #(client, _server) <- with_connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  assert ssl.accept(client, timeout) == Error(ssl.SslError("invalid socket"))
}

pub fn handshake_timeout_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_timeout({
      let assert Ok(t) = net.timeout(50)
      t
    })

  let assert Ok(address) =
    net.parse_ip_address(loopback_str)
    |> result.map(net.ip_address)

  let assert Ok(_tcp_client) =
    address
    |> tcp.new(listener_port)
    |> tcp.connect

  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(transport) = ssl.accept(listener, timeout)
  assert Error(ssl.Timeout) == ssl.handshake(transport, hs_opts)
}

pub fn handshake_with_finite_timeout_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_timeout({
      let assert Ok(t) = net.timeout(5000)
      t
    })

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      let assert Ok(_server_ssl) = ssl.handshake(transport, hs_opts)
      process.send(test_subject, Nil)
    })

  let host = net.hostname(host)

  let assert Ok(_client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

// ---------- server: handshake send/receive ---------- //

pub fn handshake_send_receive_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let hs_opts = ssl.handshake_options(data.server.cert, data.server.key)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      let assert Ok(server_ssl) = ssl.handshake(transport, hs_opts)

      // Server sends data to client
      assert Ok(Nil) == ssl.send(server_ssl, <<"from server":utf8>>)

      // Server receives data from client
      let assert Ok(<<"from client":utf8>>) =
        ssl.receive(server_ssl, 11, timeout)

      process.send(test_subject, Nil)
    })

  let host = net.hostname(host)

  let assert Ok(client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect

  // Client receives data from server
  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(<<"from server":utf8>>) = ssl.receive(client_ssl, 11, timeout)

  // Client sends data to server
  assert Ok(Nil) == ssl.send(client_ssl, <<"from client":utf8>>)

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn handshake_ec_key_test() {
  let data = testing.pkix_test_data(testing.ec(testing.Secp256r1), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let hs_opts = ssl.handshake_options(data.server.cert, data.server.key)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      let assert Ok(server_ssl) = ssl.handshake(transport, hs_opts)

      assert Ok(Nil) == ssl.send(server_ssl, <<"ec hello":utf8>>)

      let assert Ok(<<"ec reply":utf8>>) = ssl.receive(server_ssl, 8, timeout)

      process.send(test_subject, Nil)
    })

  let host = net.hostname(host)

  let assert Ok(client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(<<"ec hello":utf8>>) = ssl.receive(client_ssl, 8, timeout)

  assert Ok(Nil) == ssl.send(client_ssl, <<"ec reply":utf8>>)

  let assert Ok(_) = process.receive(test_subject, 5000)
}

// ---------- server: handshake_tcp send/receive ---------- //

pub fn handshake_tcp_send_receive_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  use ip_address <- with_ipv4_address()
  use tcp_listener <- with_tcp_listener(ip_address)

  let hs_opts = ssl.handshake_options(data.server.cert, data.server.key)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(accepted) = tcp.accept(tcp_listener.socket, timeout)

      // Server-side START-TLS upgrade
      let assert Ok(server_ssl) = ssl.handshake_from_tcp(accepted, hs_opts)

      // Server sends data to client
      assert Ok(Nil) == ssl.send(server_ssl, <<"starttls server":utf8>>)

      // Server receives data from client
      let assert Ok(<<"starttls client":utf8>>) =
        ssl.receive(server_ssl, 15, timeout)

      process.send(test_subject, Nil)
    })

  let assert Ok(address) =
    net.parse_ip_address(loopback_str)
    |> result.map(net.ip_address)

  let assert Ok(client_tcp) =
    address
    |> tcp.new(tcp_listener.port)
    |> tcp.connect

  let host = net.hostname(host)

  // Client-side upgrade
  let assert Ok(client_ssl) =
    ssl.from_tcp(client_tcp, host)
    |> ssl.verify_none
    |> ssl.connect

  // Client receives data from server
  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(<<"starttls server":utf8>>) =
    ssl.receive(client_ssl, 15, timeout)

  // Client sends data to server
  assert Ok(Nil) == ssl.send(client_ssl, <<"starttls client":utf8>>)

  let assert Ok(_) = process.receive(test_subject, 5000)
}

// ---------- ssl_not_started ---------- //

pub fn connect_ssl_not_started_test() {
  with_suppressed_logging(ssl.stop)

  use ip_address <- with_ipv4_address()
  use tcp_listener <- with_tcp_listener(ip_address)

  let host = net.hostname(host)

  assert Error(ssl.SslNotStarted)
    == ssl.new(host, tcp_listener.port)
    |> ssl.verify_none
    |> ssl.connect

  tcp.close(tcp_listener.socket)

  assert Ok(Nil) == ssl.start()
}

pub fn listen_error_test() {
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(1)

  // Port 1 is privileged so listening should fail
  let assert Error(ssl.Posix(net.Eacces)) = ssl.listen(port, loopback)
}

// ---------- server: mTLS (handshake_cacerts) ---------- //

pub fn handshake_cacerts_rejects_no_client_cert_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  // Server requires client cert verification
  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.client.cacerts)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      use <- with_suppressed_logging()

      // Server handshake should fail: client presents no certificate
      let assert Error(ssl.TlsAlert(ssl.CertificateRequired, _)) =
        ssl.handshake(transport, hs_opts)

      process.send(test_subject, Nil)
    })

  // Client connects without presenting a client certificate
  let host = net.hostname(host)

  let assert Ok(_client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn handshake_cacerts_rejects_invalid_client_cert_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)
  let wrong_data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  // Server requires client cert verification, trusts the CA that signed data's client cert
  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.client.cacerts)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      use <- with_suppressed_logging()

      // Server handshake should fail: client cert is signed by an untrusted CA
      let assert Error(ssl.TlsAlert(ssl.UnknownCa, _)) =
        ssl.handshake(transport, hs_opts)

      process.send(test_subject, Nil)
    })

  // Client connects with a certificate signed by a different CA
  let host = net.hostname(host)

  let assert Ok(_client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect_cert(wrong_data.client.cert, key: wrong_data.client.key)
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn handshake_cacerts_accepts_client_cert_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  // Server requires client cert verification, trusts the CA that signed the client cert
  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.client.cacerts)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      let assert Ok(server_ssl) = ssl.handshake(transport, hs_opts)

      // Server receives data from client
      let assert Ok(<<"mtls hello":utf8>>) =
        ssl.receive(server_ssl, 10, timeout)

      process.send(test_subject, Nil)
    })

  // Client connects WITH a certificate via the public API
  let host = net.hostname(host)

  let assert Ok(client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect_cert(data.client.cert, key: data.client.key)
    |> ssl.connect

  let assert Ok(Nil) = ssl.send(client_ssl, <<"mtls hello":utf8>>)

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn connect_cert_empty_cert_test() {
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)
  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let host = net.hostname(host)

  // Client with an empty certificate should get a validation error
  let assert Error(ssl.SslError("empty certificate")) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect_cert(<<>>, key: ssl.rsa_private_key(<<>>))
    |> ssl.connect
}

pub fn connect_cert_empty_key_test() {
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)
  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let data = testing.pkix_test_data(testing.rsa(2048), host)
  let host = net.hostname(host)

  // Client with an empty private key should get a validation error
  let assert Error(ssl.SslError("empty private key")) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect_cert(data.client.cert, key: ssl.rsa_private_key(<<>>))
    |> ssl.connect
}

type TcpListener {
  TcpListener(address: net.Address, port: net.Port, socket: tcp.Tcp)
}

type SslListener {
  SslListener(address: net.Address, port: net.Port, socket: ssl.Ssl)
}

fn with_loopback(next: fn(net.Address) -> t) -> t {
  let assert Ok(address) =
    net.parse_ip_address(loopback_str)
    |> result.map(net.ip_address)

  next(address)
}

fn with_ipv4_address(next: fn(net.IpAddress) -> t) -> t {
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)

  next(loopback)
}

fn with_ipv6_address(next: fn(net.IpAddress) -> t) -> t {
  let assert Ok(loopback) = net.ipv6_address(0, 0, 0, 0, 0, 0, 0, 1)

  next(loopback)
}

fn with_tcp_listener(ip_address: net.IpAddress, next: fn(TcpListener) -> t) -> t {
  // Set up a TCP listener, connect a client, then upgrade both sides to SSL
  let assert Ok(port) = net.port(0)
  let assert Ok(tcp_listener) = tcp.listen(port, ip_address)
  let assert Ok(port_num) = tcp.port(tcp_listener)

  let address = net.ip_address(ip_address)

  TcpListener(address:, port: port_num, socket: tcp_listener)
  |> next
}

fn with_ssl_listener(ip_address: net.IpAddress, next: fn(SslListener) -> t) -> t {
  // Set up a TCP listener, connect a client, then upgrade both sides to SSL
  let assert Ok(port) = net.port(0)
  let assert Ok(ssl_listener) = ssl.listen(port, ip_address)
  let assert Ok(port_num) = ssl.port(ssl_listener)

  let address = net.ip_address(ip_address)

  SslListener(address:, port: port_num, socket: ssl_listener)
  |> next
}

fn with_ssl_server_upgrade(
  socket: tcp.Tcp,
  subject: process.Subject(Nil),
  next: fn(testing.PkixTestData) -> t,
) -> t {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let hs_opts = ssl.handshake_options(data.server.cert, data.server.key)

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(accepted) = tcp.accept(socket, timeout)

      // Server-side upgrade: use ssl.handshake_tcp on a TCP socket
      let assert Ok(_server_ssl) = ssl.handshake_from_tcp(accepted, hs_opts)
      process.send(subject, Nil)
    })

  next(data)
}

fn with_ssl_server(
  socket: ssl.Ssl,
  subject: process.Subject(Nil),
  next: fn(testing.PkixTestData) -> t,
) -> t {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let hs_opts = ssl.handshake_options(data.server.cert, data.server.key)

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(socket, timeout)
      let assert Ok(_server_ssl) = ssl.handshake(transport, hs_opts)
      process.send(subject, Nil)
    })

  next(data)
}

fn with_connected_pair(next: fn(#(Ssl, Ssl)) -> t) -> t {
  let #(client, server) = connected_pairs()

  let res = next(#(client, server))

  assert Ok(Nil) == ssl.close(client)
  assert Ok(Nil) == ssl.close(server)

  res
}

fn connected_pairs() -> #(Ssl, Ssl) {
  let test_subject = process.new_subject()

  use ip_address <- with_ipv4_address()
  use ssl_listener <- with_ssl_listener(ip_address)

  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let hs_opts = ssl.handshake_options(data.server.cert, data.server.key)

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(ssl_listener.socket, timeout)
      let assert Ok(server_ssl) = ssl.handshake(transport, hs_opts)

      process.send(test_subject, server_ssl)
      process.receive_forever(process.new_subject())
    })

  let host = net.hostname(host)

  let assert Ok(client_ssl) =
    ssl.new(host, ssl_listener.port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(server_ssl) = process.receive(test_subject, 5000)

  #(client_ssl, server_ssl)
}

fn with_suppressed_logging(next: fn() -> t) -> t {
  suppress_logger_()

  let res = next()

  default_logger_()

  res
}

@external(erlang, "neon_test_ffi", "suppress_logger")
fn suppress_logger_() -> Nil

@external(erlang, "neon_test_ffi", "default_logger")
fn default_logger_() -> Nil

fn receive_all(socket: Ssl, remaining: Int) -> Result(BitArray, ssl.SslError) {
  use <- bool.guard(when: remaining <= 0, return: Ok(<<>>))

  let assert Ok(timeout) = net.timeout(5000)

  ssl.receive(socket, 0, timeout)
  |> result.try(fn(chunk) {
    let chunk_size = bit_array.byte_size(chunk)

    receive_all(socket, remaining - chunk_size)
    |> result.map(bit_array.append(chunk, _))
  })
}
