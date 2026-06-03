import gleam/dynamic
import gleam/erlang/atom
import gleam/erlang/process.{type Selector}
import gleam/option
import gleam/result
import neon/net

/// A TCP socket.
pub type Tcp

/// Errors that can occur during TCP operations.
pub type TcpError {
  /// The connection was closed.
  Closed
  /// The operation timed out.
  Timeout
  /// The Erlang VM can't allocate more resources for network operations.
  SystemLimit
  /// The calling process is not the current owner of the socket.
  NotOwner
  /// A POSIX error.
  Posix(net.Posix)
  /// A generic TCP error with a description.
  TcpError(String)
}

/// Messages received from a TCP socket.
pub type TcpMessage {
  /// Data received from the socket.
  Packet(Tcp, BitArray)
  /// The socket was closed.
  SocketClosed(Tcp)
  /// An error occurred on the socket.
  SocketError(Tcp, TcpError)
}

/// Options for establishing a TCP connection.
///
/// Create with `new`, then optionally configure with `ip_version` and
/// `timeout` before passing to `connect`.
pub opaque type ConnectOptions {
  ConnectOptions(
    address: net.Address,
    port: net.Port,
    ip_version: net.IpVersion,
    timeout: net.Timeout,
  )
}

/// Creates connection options for the given address and port.
///
/// Defaults to IPv4 if the address is a `net.hostname`. Default timeout is set to `infinity`.
pub fn new(address: net.Address, port: net.Port) -> ConnectOptions {
  let ip_version =
    net.address_to_ip_version(address)
    |> option.unwrap(net.Ipv4)

  ConnectOptions(address:, port:, ip_version:, timeout: net.infinity)
}

/// Sets the IP version for the connection.
pub fn ip_version(
  opts: ConnectOptions,
  ip_version: net.IpVersion,
) -> ConnectOptions {
  ConnectOptions(..opts, ip_version:)
}

/// Sets the connection timeout.
pub fn timeout(opts: ConnectOptions, timeout: net.Timeout) -> ConnectOptions {
  ConnectOptions(..opts, timeout:)
}

/// Establishes a TCP connection using the given options.
pub fn connect(opts: ConnectOptions) -> Result(Tcp, TcpError) {
  opts.address
  |> tcp_connect_(opts.port, opts.ip_version, opts.timeout)
}

/// Sends data over a TCP socket.
pub fn send(socket: Tcp, payload: BitArray) -> Result(Nil, TcpError) {
  tcp_send_(socket, payload)
}

/// Receives data from a TCP socket.
///
/// The `length` parameter specifies the number of bytes to receive. Use `0`
/// to receive whatever data is available. Must be non-negative.
pub fn receive(
  socket: Tcp,
  length: Int,
  timeout: net.Timeout,
) -> Result(BitArray, TcpError) {
  case length >= 0 {
    True -> tcp_receive_(socket, length, timeout)
    False -> Error(TcpError("Length must be non-negative"))
  }
}

/// Sets the socket to active mode.
///
/// In active mode, incoming data is delivered as messages to the socket
/// owner's mailbox. Use `select` to handle these messages.
pub fn active(socket: Tcp) -> Result(Tcp, TcpError) {
  tcp_active_(socket)
}

/// Sets the socket to passive mode.
///
/// In passive mode, data must be read explicitly using `receive`.
pub fn passive(socket: Tcp) -> Result(Tcp, TcpError) {
  tcp_passive_(socket)
}

/// Change the controlling process (owner) of a socket.
///
/// The controlling process is the process that the socket sends messages to.
pub fn controlling_process(
  socket: Tcp,
  pid: process.Pid,
) -> Result(Nil, TcpError) {
  tcp_controlling_process_(socket, pid)
}

/// Adds TCP message handlers to a selector for use with active mode sockets.
///
/// In active mode, incoming data, close notifications, and errors are
/// delivered as messages to the socket owner's mailbox. Use this function
/// to register handlers for these messages on a `Selector`.
pub fn select(selector: Selector(t), mapper: fn(TcpMessage) -> t) -> Selector(t) {
  let mapping = fn(msg) { mapper(handle_tcp_message_(msg)) }

  selector
  |> process.select_record(tag: atom.create("tcp"), fields: 2, mapping:)
  |> process.select_record(tag: atom.create("tcp_closed"), fields: 1, mapping:)
  |> process.select_record(tag: atom.create("tcp_error"), fields: 2, mapping:)
}

/// Shuts down the socket for both reading and writing.
pub fn shutdown(socket: Tcp) -> Result(Nil, TcpError) {
  tcp_shutdown_(socket)
}

/// Creates a listening TCP socket bound to the given port and IP address.
pub fn listen(
  port: net.Port,
  ip_address: net.IpAddress,
) -> Result(Tcp, TcpError) {
  tcp_listen_(port, ip_address)
}

/// Accepts an incoming connection on a listening socket.
///
/// Blocks until a connection arrives or the timeout expires.
pub fn accept(socket: Tcp, timeout: net.Timeout) -> Result(Tcp, TcpError) {
  tcp_accept_(socket, timeout)
}

/// Closes a TCP socket.
///
/// This function is idempotent and always returns `Nil`.
pub fn close(socket: Tcp) -> Nil {
  tcp_close_(socket)
}

/// Returns the port number assigned to a socket by the operating system.
///
/// Useful when listening on port 0 (OS-assigned).
pub fn port(socket: Tcp) -> Result(net.Port, Nil) {
  inet_port_(socket)
  |> result.try(net.port)
}

@external(erlang, "tcp_ffi", "active")
fn tcp_active_(socket: Tcp) -> Result(Tcp, TcpError)

@external(erlang, "tcp_ffi", "passive")
fn tcp_passive_(socket: Tcp) -> Result(Tcp, TcpError)

@external(erlang, "tcp_ffi", "handle_tcp_message")
fn handle_tcp_message_(message: dynamic.Dynamic) -> TcpMessage

@external(erlang, "tcp_ffi", "connect")
fn tcp_connect_(
  address: net.Address,
  port: net.Port,
  ip_version: net.IpVersion,
  timeout: net.Timeout,
) -> Result(Tcp, TcpError)

@external(erlang, "tcp_ffi", "recv")
fn tcp_receive_(
  socket: Tcp,
  length: Int,
  timeout: net.Timeout,
) -> Result(BitArray, TcpError)

@external(erlang, "tcp_ffi", "send")
fn tcp_send_(socket: Tcp, packet: BitArray) -> Result(Nil, TcpError)

@external(erlang, "tcp_ffi", "shutdown")
fn tcp_shutdown_(socket: Tcp) -> Result(Nil, TcpError)

@external(erlang, "tcp_ffi", "listen")
fn tcp_listen_(
  port: net.Port,
  ip_address: net.IpAddress,
) -> Result(Tcp, TcpError)

@external(erlang, "tcp_ffi", "accept")
fn tcp_accept_(listener: Tcp, timeout: net.Timeout) -> Result(Tcp, TcpError)

@external(erlang, "tcp_ffi", "close")
fn tcp_close_(socket: Tcp) -> Nil

@external(erlang, "tcp_ffi", "controlling_process")
fn tcp_controlling_process_(
  socket: Tcp,
  pid: process.Pid,
) -> Result(Nil, TcpError)

@external(erlang, "inet_ffi", "port")
fn inet_port_(socket: Tcp) -> Result(Int, Nil)
