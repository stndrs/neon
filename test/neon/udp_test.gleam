import gleam/erlang/process
import gleam/result
import neon/net
import neon/udp

// ---------- connect ---------- //

const host = "127.0.0.1"

pub fn open_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(_sock) = udp.new(port) |> udp.open
}

pub fn open_error_test() {
  let assert Ok(port) = net.port(1)
  // Port 1 is privileged so opening should fail
  assert Error(udp.Posix(net.Eacces)) == udp.new(port) |> udp.open
}

pub fn port_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open
  let assert Ok(port) = udp.port(sock)

  assert net.port_to_int(port) > 0
}

pub fn connect_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open
  let assert Ok(port_num) = udp.port(sock)
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  assert Ok(Nil) == udp.connect(sock, address, port_num)
}

pub fn connect_closed_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  udp.close(sock)

  let assert Ok(closed_port) = net.port(8000)
  assert Error(udp.Closed) == udp.connect(sock, address, closed_port)
}

pub fn send_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open
  let assert Ok(port_num) = udp.port(sock)
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  assert Ok(Nil) == udp.connect(sock, address, port_num)

  assert Ok(Nil) == udp.send(sock, <<"hello":utf8>>)
}

pub fn send_closed_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open
  let assert Ok(port_num) = udp.port(sock)
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  assert Ok(Nil) == udp.connect(sock, address, port_num)

  udp.close(sock)

  assert Error(udp.Closed) == udp.send(sock, <<"hello":utf8>>)
}

// ---------- receive ---------- //

pub fn receive_test() {
  let assert Ok(port) = net.port(0)
  // Open a receiver socket and a sender socket
  let assert Ok(receiver) = udp.new(port) |> udp.open
  let assert Ok(receiver_port) = udp.port(receiver)

  let assert Ok(sender) = udp.new(port) |> udp.open
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  assert Ok(Nil) == udp.connect(sender, address, receiver_port)
  assert Ok(Nil) == udp.send(sender, <<"hello":utf8>>)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(udp.ReceiveData(
    ip_address: recv_ip,
    port: _sender_port,
    payload: <<"hello":utf8>>,
  )) = udp.receive(receiver, 0, timeout)
  assert recv_ip == loopback
}

pub fn receive_negative_length_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  let assert Ok(timeout) = net.timeout(1000)
  assert Error(udp.UdpError("Length must be non-negative"))
    == udp.receive(sock, -1, timeout)
}

pub fn receive_timeout_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  // No data is sent, so receive should time out
  let assert Ok(timeout) = net.timeout(100)
  assert Error(udp.Timeout) == udp.receive(sock, 0, timeout)
}

pub fn receive_forever_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(receiver) = udp.new(port) |> udp.open
  let assert Ok(receiver_port) = udp.port(receiver)
  let test_subject = process.new_subject()

  // Spawn a process that sends data, since receive with Infinity blocks
  let _pid =
    process.spawn(fn() {
      let assert Ok(sender) = udp.new(port) |> udp.open
      let assert Ok(address) =
        net.parse_ip_address(host)
        |> result.map(net.ip_address)
      assert Ok(Nil) == udp.connect(sender, address, receiver_port)
      assert Ok(Nil) == udp.send(sender, <<"world":utf8>>)
      process.send(test_subject, Nil)
    })

  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(udp.ReceiveData(
    ip_address: recv_ip,
    port: _sender_port,
    payload: <<"world":utf8>>,
  )) = udp.receive(receiver, 0, net.infinity)
  assert recv_ip == loopback

  // Wait for the sender process to finish
  let assert Ok(_) = process.receive(test_subject, 1000)
}

pub fn receive_forever_closed_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  udp.close(sock)

  assert Error(udp.Closed) == udp.receive(sock, 0, net.infinity)
}

// ---------- connect and send/receive ---------- //

pub fn connect_send_receive_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(receiver) = udp.new(port) |> udp.open
  let assert Ok(receiver_port) = udp.port(receiver)

  let assert Ok(sender) = udp.new(port) |> udp.open
  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  // Connect sender, then send and receive
  assert Ok(Nil) == udp.connect(sender, address, receiver_port)
  assert Ok(Nil) == udp.send(sender, <<"connected send":utf8>>)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(loopback) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(udp.ReceiveData(
    ip_address: recv_ip,
    port: _sender_port,
    payload: <<"connected send":utf8>>,
  )) = udp.receive(receiver, 0, timeout)
  assert recv_ip == loopback
}

pub fn receive_on_connected_socket_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock_a) = udp.new(port) |> udp.open
  let assert Ok(port_a) = udp.port(sock_a)

  let assert Ok(sock_b) = udp.new(port) |> udp.open
  let assert Ok(port_b) = udp.port(sock_b)

  let assert Ok(address) =
    net.parse_ip_address(host)
    |> result.map(net.ip_address)

  // Connect both sockets to each other
  assert Ok(Nil) == udp.connect(sock_a, address, port_b)
  assert Ok(Nil) == udp.connect(sock_b, address, port_a)

  // Send from A, receive on connected B
  assert Ok(Nil) == udp.send(sock_a, <<"from a":utf8>>)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(udp.ReceiveData(
    ip_address: _ip,
    port: _port,
    payload: <<"from a":utf8>>,
  )) = udp.receive(sock_b, 0, timeout)
}

// ---------- open options ---------- //

pub fn open_with_ipv4_version_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) =
    udp.new(port)
    |> udp.ip_version(net.Ipv4)
    |> udp.open

  let assert Ok(assigned_port) = udp.port(sock)
  assert net.port_to_int(assigned_port) > 0

  udp.close(sock)
}

pub fn open_with_ip_address_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(addr) = net.ipv4_address(127, 0, 0, 1)
  let assert Ok(sock) = udp.new(port) |> udp.ip_address(addr) |> udp.open

  let assert Ok(assigned_port) = udp.port(sock)
  assert net.port_to_int(assigned_port) > 0

  udp.close(sock)
}

pub fn open_ipv6_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(addr) = net.ipv6_address(0, 0, 0, 0, 0, 0, 0, 1)
  let assert Ok(sock) = udp.new(port) |> udp.ip_address(addr) |> udp.open

  let assert Ok(assigned_port) = udp.port(sock)
  assert net.port_to_int(assigned_port) > 0

  // Send and receive on IPv6 loopback
  assert Ok(Nil) == udp.connect(sock, net.ip_address(addr), assigned_port)
  assert Ok(Nil) == udp.send(sock, <<"ipv6":utf8>>)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(udp.ReceiveData(
    ip_address: recv_ip,
    port: _sender_port,
    payload: <<"ipv6":utf8>>,
  )) = udp.receive(sock, 0, timeout)
  assert recv_ip == addr

  udp.close(sock)
}

pub fn ipv6_send_receive_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(addr) = net.ipv6_address(0, 0, 0, 0, 0, 0, 0, 1)

  let assert Ok(receiver) = udp.new(port) |> udp.ip_address(addr) |> udp.open
  let assert Ok(receiver_port) = udp.port(receiver)

  let assert Ok(sender) = udp.new(port) |> udp.ip_address(addr) |> udp.open

  let address = net.ip_address(addr)
  assert Ok(Nil) == udp.connect(sender, address, receiver_port)
  assert Ok(Nil) == udp.send(sender, <<"ipv6 data":utf8>>)

  let assert Ok(timeout) = net.timeout(1000)
  let assert Ok(udp.ReceiveData(
    ip_address: recv_ip,
    port: _sender_port,
    payload: <<"ipv6 data":utf8>>,
  )) = udp.receive(receiver, 0, timeout)
  assert recv_ip == addr

  udp.close(sender)
  udp.close(receiver)
}

// ---------- controlling_process ---------- //

pub fn controlling_process_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  let pid = process.spawn(fn() { process.sleep(1000) })

  assert udp.controlling_process(sock, pid) == Ok(Nil)
}

pub fn controlling_process_close_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  udp.close(sock)

  assert udp.controlling_process(sock, process.self()) == Error(udp.Closed)
}

pub fn controlling_process_invalid_pid_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  // Spawn a process that immediately exits
  let pid = process.spawn(fn() { Nil })
  process.sleep(10)

  assert udp.controlling_process(sock, pid)
    == Error(udp.UdpError("invalid pid"))
}

// ---------- close ---------- //

pub fn close_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  udp.close(sock)
  udp.close(sock)
}

pub fn close_receive_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  udp.close(sock)

  // Receiving on a closed socket should fail
  let assert Ok(timeout) = net.timeout(100)
  assert Error(udp.Closed) == udp.receive(sock, 0, timeout)
}

// ---------- port ---------- //

pub fn port_closed_test() {
  let assert Ok(port) = net.port(0)
  let assert Ok(sock) = udp.new(port) |> udp.open

  udp.close(sock)

  assert Error(Nil) == udp.port(sock)
}
