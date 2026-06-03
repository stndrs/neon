import gleam/erlang/process
import gleam/result
import neon/net
import neon/tcp.{type Tcp}

// ---------- connect ---------- //

const host = "127.0.0.1"

pub fn port_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(tcp) = tcp.listen(port, loopback)

  let assert Ok(port) = tcp.port(tcp)

  assert net.port_to_int(port) > 0
}

pub fn connect_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(tcp_port) = tcp.listen(port, loopback)

  let assert Ok(port_num) = tcp.port(tcp_port)
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  let assert Ok(_socket) =
    address
    |> tcp.new(port_num)
    |> tcp.connect
}

pub fn connect_ipv6_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(loopback) = net.ipv6_address(0, 0, 0, 0, 0, 0, 0, 1)
  let assert Ok(tcp_port) = tcp.listen(port, loopback)

  let assert Ok(port_num) = tcp.port(tcp_port)
  let assert Ok(address) =
    net.parse_ip_address("::1")
    |> result.map(net.ip_address)

  let assert Ok(_socket) =
    address
    |> tcp.new(port_num)
    |> tcp.ip_version(net.Ipv6)
    |> tcp.connect
}

pub fn connect_hostname_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(listener) = tcp.listen(port, loopback)

  let assert Ok(port_num) = tcp.port(listener)
  let address = net.hostname("localhost")

  let assert Ok(_socket) =
    address
    |> tcp.new(port_num)
    |> tcp.connect
}

pub fn connect_error_test() {
  let assert Ok(port) = net.port(1)
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  let assert Error(tcp.Posix(net.Econnrefused)) =
    address
    |> tcp.new(port)
    |> tcp.ip_version(net.Ipv4)
    |> tcp.connect
}

// ---------- listen ---------- //

pub fn listen_error_test() {
  let assert Ok(port) = net.port(1)

  // Port 1 is privileged so listening should fail
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Error(tcp.Posix(net.Eacces)) = tcp.listen(port, loopback)
}

// ---------- accept ---------- //

pub fn accept_timeout_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(listener) = tcp.listen(port, loopback)

  // No client connects, so accept should time out
  let assert Ok(timeout) = net.timeout(50)
  let assert Error(tcp.Timeout) = tcp.accept(listener, timeout)
}

// ---------- send ---------- //

pub fn send_test() {
  let #(socket, _listener) = connected_pair()

  let assert Ok(Nil) = tcp.send(socket, <<"hello":utf8>>)
  let assert Ok(Nil) = tcp.shutdown(socket)
}

pub fn send_closed_test() {
  let #(socket, _listener) = connected_pair()

  let assert Ok(_) = tcp.shutdown(socket)
  let assert Error(tcp.Closed) = tcp.send(socket, <<"hello":utf8>>)
}

// ---------- receive ---------- //

pub fn receive_test() {
  let #(socket, listener) = connected_pair()

  // Accept the connection on the server side and send data
  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(server_sock) = tcp.accept(listener, timeout)
  let assert Ok(_) = tcp.send(server_sock, <<"hello":utf8>>)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"hello":utf8>>) = tcp.receive(socket, 5, timeout)

  let assert Ok(_) = tcp.shutdown(socket)
}

pub fn receive_timeout_test() {
  let #(socket, _listener) = connected_pair()

  // No data is sent, so receive should time out
  let assert Ok(timeout) = net.timeout(100)
  let assert Error(tcp.Timeout) = tcp.receive(socket, 1, timeout)

  let assert Ok(_) = tcp.shutdown(socket)
}

pub fn receive_closed_test() {
  let #(socket, listener) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(server_sock) = tcp.accept(listener, timeout)
  tcp.close(server_sock)

  process.sleep(50)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Error(tcp.Closed) = tcp.receive(socket, 1, timeout)
}

pub fn receive_forever_test() {
  let #(socket, listener) = connected_pair()
  let test_subject = process.new_subject()

  // Spawn a process that accepts and sends data, since receive with infinity blocks
  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(server_sock) = tcp.accept(listener, timeout)
      let assert Ok(_) = tcp.send(server_sock, <<"world":utf8>>)
      process.send(test_subject, Nil)
    })

  let assert Ok(<<"world":utf8>>) = tcp.receive(socket, 5, net.infinity)

  // Wait for the sender process to finish
  let assert Ok(_) = process.receive(test_subject, 1000)

  let assert Ok(_) = tcp.shutdown(socket)
}

pub fn receive_forever_closed_test() {
  let #(socket, listener) = connected_pair()

  let _pid =
    process.spawn(fn() {
      let assert Ok(timeout) = net.timeout(5000)
      let assert Ok(server_sock) = tcp.accept(listener, timeout)
      tcp.close(server_sock)
    })

  let assert Error(tcp.Closed) = tcp.receive(socket, 1, net.infinity)
}

pub fn receive_negative_length_test() {
  let #(socket, _listener) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Error(tcp.TcpError("Length must be non-negative")) =
    tcp.receive(socket, -1, timeout)
}

// ---------- close ---------- //

pub fn close_test() {
  let #(socket, listener) = connected_pair()

  assert Nil == tcp.close(socket)
  assert Nil == tcp.close(socket)

  assert Nil == tcp.close(listener)
  assert Nil == tcp.close(listener)
}

// ---------- shutdown ---------- //

pub fn shutdown_test() {
  let #(socket, _listener) = connected_pair()

  let assert Ok(Nil) = tcp.shutdown(socket)
}

pub fn shutdown_closed_test() {
  let #(socket, listener) = connected_pair()

  // Close the underlying port entirely so shutdown will fail
  assert Nil == tcp.close(socket)
  assert Nil == tcp.close(listener)

  let assert Error(tcp.Closed) = tcp.shutdown(socket)
}

// ---------- active ---------- //

pub fn active_test() {
  let #(client, listener) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(server) = tcp.accept(listener, timeout)

  // Put client into active mode
  let assert Ok(_) = tcp.active(client)

  // Server sends data
  let assert Ok(Nil) = tcp.send(server, <<"hello active":utf8>>)

  // Client receives data as a TcpMessage via selector
  let selector =
    process.new_selector()
    |> tcp.select(fn(msg) { msg })

  let assert Ok(tcp.Packet(_, <<"hello active":utf8>>)) =
    process.selector_receive(from: selector, within: 1000)
}

pub fn active_closed_test() {
  let #(client, listener) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(server) = tcp.accept(listener, timeout)

  // Put client into active mode
  let assert Ok(_) = tcp.active(client)

  // Server closes its side
  tcp.close(server)

  // Client receives SocketClosed message
  let selector =
    process.new_selector()
    |> tcp.select(fn(msg) { msg })

  let assert Ok(tcp.SocketClosed(_)) =
    process.selector_receive(from: selector, within: 1000)
}

pub fn passive_test() {
  let #(client, listener) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(server) = tcp.accept(listener, timeout)

  // Put client into active mode, then immediately back to passive
  let assert Ok(client) = tcp.active(client)
  let assert Ok(_) = tcp.passive(client)

  // Server sends data
  let assert Ok(Nil) = tcp.send(server, <<"passive data":utf8>>)

  // Give data time to arrive at the socket
  process.sleep(50)

  // No message should be delivered since socket is passive
  let selector =
    process.new_selector()
    |> tcp.select(fn(msg) { msg })

  let assert Error(Nil) = process.selector_receive(from: selector, within: 100)

  // But synchronous receive should work
  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"passive data":utf8>>) = tcp.receive(client, 0, timeout)
}

pub fn active_then_passive_test() {
  let #(client, listener) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(server) = tcp.accept(listener, timeout)

  // Put client into active mode
  let assert Ok(client) = tcp.active(client)

  // Server sends first message
  let assert Ok(Nil) = tcp.send(server, <<"first":utf8>>)

  // Client receives first message via selector
  let selector =
    process.new_selector()
    |> tcp.select(fn(msg) { msg })

  let assert Ok(tcp.Packet(_, <<"first":utf8>>)) =
    process.selector_receive(from: selector, within: 1000)

  // Switch to passive
  let assert Ok(_) = tcp.passive(client)

  // Server sends second message
  let assert Ok(Nil) = tcp.send(server, <<"second":utf8>>)

  // Give data time to arrive
  process.sleep(50)

  // Client receives second message synchronously
  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(<<"second":utf8>>) = tcp.receive(client, 0, timeout)
}

pub fn controlling_process_test() {
  let #(client, listener) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(server) = tcp.accept(listener, timeout)

  // Switch to active mode
  let assert Ok(client) = tcp.active(client)

  // Create a process for receiving a message
  let pid =
    process.spawn(fn() {
      let selector =
        process.new_selector()
        |> tcp.select(fn(msg) { msg })

      assert process.selector_receive_forever(from: selector)
        == tcp.Packet(client, <<"foo!":utf8>>)
    })

  assert tcp.controlling_process(client, pid) == Ok(Nil)

  assert Ok(Nil) == tcp.send(server, <<"foo!":utf8>>)
}

pub fn controlling_process_close_test() {
  let #(client, listener) = connected_pair()

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(_) = tcp.accept(listener, timeout)

  // Closes the socket on server side
  tcp.close(client)

  assert tcp.controlling_process(client, process.self()) == Error(tcp.Closed)
}

// Creates a TCP listener on an OS-assigned port, connects a client socket
// to it, and returns the client socket along with the listener port
fn connected_pair() -> #(Tcp, Tcp) {
  let assert Ok(port) = net.port(0)
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(listener) = tcp.listen(port, loopback)

  let assert Ok(port_num) = tcp.port(listener)
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)
  let assert Ok(socket) =
    address
    |> tcp.new(port_num)
    |> tcp.connect

  #(socket, listener)
}
