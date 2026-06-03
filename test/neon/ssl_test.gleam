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
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  // Set up a TCP listener, connect a client, then upgrade both sides to SSL
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)
  let assert Ok(tcp_listener) = tcp.listen(port, loopback)
  let assert Ok(port_num) = tcp.port(tcp_listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.server.cacerts)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(accepted) = tcp.accept(tcp_listener, timeout)

      // Server-side upgrade: use ssl.handshake_tcp on a TCP socket
      let assert Ok(_server_ssl) = ssl.handshake_from_tcp(accepted, hs_opts)
      process.send(test_subject, Nil)
    })

  let assert Ok(address) =
    net.parse_ip_address(loopback_str)
    |> result.map(net.ip_address)

  let assert Ok(client_tcp) =
    address
    |> tcp.new(port_num)
    |> tcp.connect

  // Client-side upgrade
  let assert Ok(_ssl_socket) =
    ssl.from_tcp(client_tcp, host)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

// ---------- connect ---------- //

pub fn connect_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(port_num) = ssl.port(listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.server.cacerts)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      let assert Ok(_server_ssl) = ssl.handshake(transport, hs_opts)
      process.send(test_subject, Nil)
    })

  let assert Ok(_ssl_socket) =
    ssl.new(host, port_num)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

pub fn connect_verify_peer_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(tcp_listener) = tcp.listen(port, loopback)
  let assert Ok(port_num) = tcp.port(tcp_listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.server.cacerts)

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(accepted) = tcp.accept(tcp_listener, timeout)
      let assert Ok(_server_ssl) = ssl.handshake_from_tcp(accepted, hs_opts)
    })

  let assert Ok(address) =
    net.parse_ip_address(loopback_str)
    |> result.map(net.ip_address)

  let assert Ok(client_tcp) =
    address
    |> tcp.new(port_num)
    |> tcp.connect

  let assert Ok(_ssl_socket) =
    ssl.from_tcp(client_tcp, host)
    |> ssl.verify_peer
    |> ssl.connect_cacerts(data.server.cacerts)
    |> ssl.connect
}

pub fn connect_timeout_test() {
  // Listen but never accept
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)
  let assert Ok(tcp_listener) = tcp.listen(port, loopback)
  let assert Ok(port_num) = tcp.port(tcp_listener)

  let assert Ok(short_timeout) = net.timeout(50)

  let assert Error(ssl.Timeout) =
    ssl.new(host, port_num)
    |> ssl.verify_none
    |> ssl.timeout(short_timeout)
    |> ssl.connect

  tcp.close(tcp_listener)
}

pub fn connect_error_test() {
  let assert Ok(port) = net.port(1)

  let assert Error(ssl.Posix(net.Econnrefused)) =
    ssl.new(host, port)
    |> ssl.connect
}

pub fn connect_tls_alert_unknown_ca_test() {
  let server_data = testing.pkix_test_data(testing.rsa(2048), host)
  let wrong_ca_data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(port_num) = ssl.port(listener)

  let hs_opts =
    ssl.handshake_options(server_data.server.cert, server_data.server.key)
    |> ssl.handshake_cacerts(server_data.server.cacerts)

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      suppress_logger_()

      let _result = ssl.handshake(transport, hs_opts)

      default_logger_()
    })

  // The client trusts the wrong CA and should get UnknownCa alert
  let assert Error(ssl.TlsAlert(ssl.UnknownCa, _description)) =
    ssl.new(host, port_num)
    |> ssl.verify_peer
    |> ssl.connect_cacerts(wrong_ca_data.client.cacerts)
    |> ssl.connect
}

pub fn upgrade_error_test() {
  let assert Ok(port) = net.port(0)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(listener) = tcp.listen(port, loopback)

  let assert Ok(port_num) = tcp.port(listener)

  let test_subject = process.new_subject()
  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(accepted) = tcp.accept(listener, timeout)

      let _ = tcp.close(accepted)
      process.send(test_subject, Nil)
    })

  let assert Ok(address) =
    net.parse_ip_address(loopback_str)
    |> result.map(net.ip_address)

  let assert Ok(socket) =
    address
    |> tcp.new(port_num)
    |> tcp.connect

  let assert Error(ssl.Closed) =
    ssl.from_tcp(socket, host)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(_) = process.receive(test_subject, 5000)
}

// ---------- send ---------- //

pub fn send_test() {
  let #(ssl_socket, _server_ssl) = connected_pair()

  let assert Ok(Nil) = ssl.send(ssl_socket, <<"hello ssl":utf8>>)
  let assert Ok(Nil) = ssl.shutdown(ssl_socket)
}

pub fn send_closed_test() {
  let #(ssl_socket, _server_ssl) = connected_pair()

  let assert Ok(_) = ssl.shutdown(ssl_socket)
  process.sleep(50)
  let assert Error(ssl.Closed) = ssl.send(ssl_socket, <<"hello":utf8>>)
}

// ---------- receive ---------- //

pub fn receive_test() {
  let #(ssl_socket, server_ssl) = connected_pair()

  // Server sends data over SSL
  let assert Ok(_) = ssl.send(server_ssl, <<"hello ssl":utf8>>)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"hello ssl":utf8>>) = ssl.receive(ssl_socket, 9, timeout)
}

pub fn receive_timeout_test() {
  let #(ssl_socket, server_ssl) = connected_pair()

  // No data is sent, so receive should time out
  let assert Ok(timeout) = net.timeout(100)
  let assert Error(ssl.Timeout) = ssl.receive(ssl_socket, 1, timeout)

  let _ = ssl.close(server_ssl)
}

pub fn receive_forever_test() {
  let #(ssl_socket, server_ssl) = connected_pair()
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
  let #(ssl_socket, _server_ssl) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Error(ssl.SslError("Length must be non-negative")) =
    ssl.receive(ssl_socket, -1, timeout)
}

pub fn receive_closed_test() {
  let #(ssl_socket, server_ssl) = connected_pair()

  let assert Ok(Nil) = ssl.close(server_ssl)

  process.sleep(50)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Error(ssl.Closed) = ssl.receive(ssl_socket, 1, timeout)
}

pub fn receive_forever_closed_test() {
  let #(ssl_socket, server_ssl) = connected_pair()
  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(Nil) = ssl.close(server_ssl)
      process.send(test_subject, Nil)
    })

  let assert Error(ssl.Closed) = ssl.receive(ssl_socket, 1, net.infinity)

  let assert Ok(_) = process.receive(test_subject, 1000)
}

// ---------- close ---------- //

pub fn close_test() {
  let #(ssl_socket, server_ssl) = connected_pair()

  let assert Ok(Nil) = ssl.close(ssl_socket)
  let assert Ok(Nil) = ssl.close(ssl_socket)

  let assert Ok(Nil) = ssl.close(server_ssl)
  let assert Ok(Nil) = ssl.close(server_ssl)
}

// ---------- shutdown ---------- //

pub fn shutdown_test() {
  let #(ssl_socket, _server_ssl) = connected_pair()

  let assert Ok(Nil) = ssl.shutdown(ssl_socket)
}

pub fn shutdown_closed_test() {
  let #(ssl_socket, server_ssl) = connected_pair()

  let assert Ok(Nil) = ssl.close(server_ssl)

  process.sleep(50)

  let assert Error(ssl.Closed) = ssl.shutdown(ssl_socket)
}

// ---------- active ---------- //

pub fn active_test() {
  let #(client, server) = connected_pair()

  // Put client into active mode
  let assert Ok(_) = ssl.active(client)

  // Server sends data
  let assert Ok(Nil) = ssl.send(server, <<"hello active":utf8>>)

  // Client receives data as an SslMessage via selector
  let selector =
    process.new_selector()
    |> ssl.select(fn(msg) { msg })

  let assert Ok(ssl.Packet(_, <<"hello active":utf8>>)) =
    process.selector_receive(from: selector, within: 1000)
}

pub fn active_closed_test() {
  let #(client, server) = connected_pair()

  // Put client into active mode
  let assert Ok(_) = ssl.active(client)

  // Server closes its side
  let assert Ok(Nil) = ssl.close(server)

  // Client receives SocketClosed message
  let selector =
    process.new_selector()
    |> ssl.select(fn(msg) { msg })

  let assert Ok(ssl.SocketClosed(_)) =
    process.selector_receive(from: selector, within: 1000)
}

pub fn passive_test() {
  let #(client, server) = connected_pair()

  // Put client into active mode, then immediately back to passive
  let assert Ok(client) = ssl.active(client)
  let assert Ok(_) = ssl.passive(client)

  // Server sends data
  let assert Ok(Nil) = ssl.send(server, <<"passive data":utf8>>)

  // Give data time to arrive at the socket
  process.sleep(50)

  // No message should be delivered since socket is passive
  let selector =
    process.new_selector()
    |> ssl.select(fn(msg) { msg })

  let assert Error(Nil) = process.selector_receive(from: selector, within: 100)

  // But synchronous receive should work
  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"passive data":utf8>>) = ssl.receive(client, 0, timeout)
}

pub fn active_then_passive_test() {
  let #(client, server) = connected_pair()

  // Put client into active mode
  let assert Ok(client) = ssl.active(client)

  // Server sends first message
  let assert Ok(Nil) = ssl.send(server, <<"first":utf8>>)

  // Client receives first message via selector
  let selector =
    process.new_selector()
    |> ssl.select(fn(msg) { msg })

  let assert Ok(ssl.Packet(_, <<"first":utf8>>)) =
    process.selector_receive(from: selector, within: 1000)

  // Switch to passive
  let assert Ok(_) = ssl.passive(client)

  // Server sends second message
  let assert Ok(Nil) = ssl.send(server, <<"second":utf8>>)

  // Give data time to arrive
  process.sleep(50)

  // Client receives second message synchronously
  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"second":utf8>>) = ssl.receive(client, 0, timeout)
}

pub fn controlling_process_test() {
  let #(client, server) = connected_pair()

  // Switch to active mode
  let assert Ok(client) = ssl.active(client)

  // Create a process for receiving a message
  let pid =
    process.spawn(fn() {
      let selector =
        process.new_selector()
        |> ssl.select(fn(msg) { msg })

      assert process.selector_receive_forever(from: selector)
        == ssl.Packet(client, <<"foo!":utf8>>)
    })

  assert ssl.controlling_process(client, pid) == Ok(Nil)

  assert Ok(Nil) == ssl.send(server, <<"foo!":utf8>>)
}

pub fn controlling_process_close_test() {
  let #(client, _server) = connected_pair()

  // Closes the socket on server side
  assert ssl.close(client) == Ok(Nil)

  assert ssl.controlling_process(client, process.self()) == Error(ssl.Closed)
}

// ---------- port ---------- //

pub fn port_test() {
  let #(client_ssl, server_ssl) = connected_pair()

  let assert Ok(client_port) = ssl.port(client_ssl)
  assert net.port_to_int(client_port) > 0

  let assert Ok(server_port) = ssl.port(server_ssl)
  assert net.port_to_int(server_port) > 0
}

pub fn port_closed_test() {
  let #(ssl_socket, _server_ssl) = connected_pair()

  let assert Ok(Nil) = ssl.close(ssl_socket)

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
  let assert Error(ssl.Timeout) = ssl.accept(listener, timeout)
}

pub fn handshake_timeout_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.server.cacerts)
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
  let assert Error(ssl.Timeout) = ssl.handshake(transport, hs_opts)
}

// ---------- server: handshake send/receive ---------- //

pub fn handshake_send_receive_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.server.cacerts)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      let assert Ok(server_ssl) = ssl.handshake(transport, hs_opts)

      // Server sends data to client
      let assert Ok(Nil) = ssl.send(server_ssl, <<"from server":utf8>>)

      // Server receives data from client
      let assert Ok(<<"from client":utf8>>) =
        ssl.receive(server_ssl, 11, timeout)

      process.send(test_subject, Nil)
    })

  let assert Ok(client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect

  // Client receives data from server
  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(<<"from server":utf8>>) = ssl.receive(client_ssl, 11, timeout)

  // Client sends data to server
  let assert Ok(Nil) = ssl.send(client_ssl, <<"from client":utf8>>)

  let assert Ok(_) = process.receive(test_subject, 5000)
}

// ---------- server: handshake_tcp send/receive ---------- //

pub fn handshake_tcp_send_receive_test() {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)
  let assert Ok(tcp_listener) = tcp.listen(port, loopback)
  let assert Ok(listener_port) = tcp.port(tcp_listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.server.cacerts)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(accepted) = tcp.accept(tcp_listener, timeout)

      // Server-side START-TLS upgrade
      let assert Ok(server_ssl) = ssl.handshake_from_tcp(accepted, hs_opts)

      // Server sends data to client
      let assert Ok(Nil) = ssl.send(server_ssl, <<"starttls server":utf8>>)

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
    |> tcp.new(listener_port)
    |> tcp.connect

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
  let assert Ok(Nil) = ssl.send(client_ssl, <<"starttls client":utf8>>)

  let assert Ok(_) = process.receive(test_subject, 5000)
}

// ---------- ssl_not_started ---------- //

pub fn connect_ssl_not_started_test() {
  suppress_logger_()

  ssl.stop()

  default_logger_()

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)
  let assert Ok(tcp_listener) = tcp.listen(port, loopback)
  let assert Ok(port_num) = tcp.port(tcp_listener)

  let assert Error(ssl.SslNotStarted) =
    ssl.new(host, port_num)
    |> ssl.verify_none
    |> ssl.connect

  tcp.close(tcp_listener)

  let assert Ok(Nil) = ssl.start()
}

fn connected_pair() -> #(Ssl, Ssl) {
  let data = testing.pkix_test_data(testing.rsa(2048), host)

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(port) = net.port(0)

  let assert Ok(listener) = ssl.listen(port, loopback)
  let assert Ok(listener_port) = ssl.port(listener)

  let hs_opts =
    ssl.handshake_options(data.server.cert, data.server.key)
    |> ssl.handshake_cacerts(data.server.cacerts)

  let test_subject = process.new_subject()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(transport) = ssl.accept(listener, timeout)
      let assert Ok(server_ssl) = ssl.handshake(transport, hs_opts)

      process.send(test_subject, server_ssl)
      process.receive_forever(process.new_subject())
    })

  let assert Ok(client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(server_ssl) = process.receive(test_subject, 5000)

  #(client_ssl, server_ssl)
}

@external(erlang, "neon_test_ffi", "suppress_logger")
fn suppress_logger_() -> Nil

@external(erlang, "neon_test_ffi", "default_logger")
fn default_logger_() -> Nil
