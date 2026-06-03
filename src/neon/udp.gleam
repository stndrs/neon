import gleam/erlang/process
import gleam/option.{type Option, None, Some}
import gleam/result
import neon/net

/// A UDP socket.
pub type Udp

/// Errors that can occur during UDP operations.
pub type UdpError {
  /// The socket was closed.
  Closed
  /// The operation timed out.
  Timeout
  /// The Erlang VM can't allocate more resources for network operations.
  SystemLimit
  /// A POSIX error.
  Posix(net.Posix)
  /// The target pid is not alive.
  InvalidPid
  /// A generic UDP error with a description.
  UdpError(String)
}

/// Options for opening a UDP socket.
///
/// Create with `new`, then optionally configure with `ip_address` and
/// `ip_version` before passing to `open`.
pub opaque type OpenOptions {
  OpenOptions(
    port: net.Port,
    ip_address: Option(net.IpAddress),
    ip_version: net.IpVersion,
  )
}

/// Creates open options for a UDP socket on the given port.
///
/// Defaults to IPv4 with no specific IP address binding.
pub fn new(port: net.Port) -> OpenOptions {
  OpenOptions(port:, ip_address: None, ip_version: net.Ipv4)
}

/// Binds the socket to a specific IP address.
///
/// When set, the IP version is derived from the address itself, and the
/// `ip_version` option is ignored.
pub fn ip_address(opts: OpenOptions, ip_address: net.IpAddress) -> OpenOptions {
  OpenOptions(..opts, ip_address: Some(ip_address))
}

/// Sets the IP version for the socket.
///
/// Only used when no IP address is set. When an IP address is provided,
/// the version is derived from the address.
pub fn ip_version(opts: OpenOptions, ip_version: net.IpVersion) -> OpenOptions {
  OpenOptions(..opts, ip_version:)
}

/// Opens a UDP socket with the given options.
pub fn open(opts: OpenOptions) -> Result(Udp, UdpError) {
  udp_open_(opts.port, opts.ip_address, opts.ip_version)
}

/// Associates a UDP socket with a remote address and port.
///
/// After connecting, `send` can be used without specifying a destination.
pub fn connect(
  socket: Udp,
  address: net.Address,
  port: net.Port,
) -> Result(Nil, UdpError) {
  udp_connect_(socket, address, port)
}

/// Sends data over a connected UDP socket.
pub fn send(socket: Udp, payload: BitArray) -> Result(Nil, UdpError) {
  udp_send_(socket, payload)
}

/// Data received from a UDP socket, including the sender's IP address,
/// port, and the payload.
pub type ReceiveData {
  ReceiveData(ip_address: net.IpAddress, port: net.Port, payload: BitArray)
}

/// Receives data from a UDP socket.
///
/// The `length` parameter specifies the number of bytes to receive. Use `0`
/// to receive whatever data is available. Must be non-negative.
pub fn receive(
  socket: Udp,
  length: Int,
  timeout: net.Timeout,
) -> Result(ReceiveData, UdpError) {
  case length >= 0 {
    True ->
      udp_receive_(socket, length, timeout)
      |> result.map(fn(recv_data) {
        let #(ip_address, port, payload) = recv_data

        ReceiveData(ip_address:, port:, payload:)
      })
    False -> Error(UdpError("Length must be non-negative"))
  }
}

/// Change the controlling process of a socket.
///
/// The controlling process is the process that the socket sends messages to.
pub fn controlling_process(
  socket: Udp,
  pid: process.Pid,
) -> Result(Nil, UdpError) {
  udp_controlling_process_(socket, pid)
}

/// Closes a UDP socket.
///
/// This function is idempotent and always returns `Nil`.
pub fn close(socket: Udp) -> Nil {
  udp_close_(socket)
}

/// Returns the port number assigned to a socket by the operating system.
///
/// Useful when opening on port 0 (OS-assigned).
pub fn port(socket: Udp) -> Result(net.Port, Nil) {
  inet_port_(socket)
  |> result.try(net.port)
}

@external(erlang, "udp_ffi", "open")
fn udp_open_(
  port: net.Port,
  ip_address: Option(net.IpAddress),
  ip_version: net.IpVersion,
) -> Result(Udp, UdpError)

@external(erlang, "udp_ffi", "connect")
fn udp_connect_(
  socket: Udp,
  address: net.Address,
  port: net.Port,
) -> Result(Nil, UdpError)

@external(erlang, "udp_ffi", "send")
fn udp_send_(socket: Udp, payload: BitArray) -> Result(Nil, UdpError)

@external(erlang, "udp_ffi", "recv")
fn udp_receive_(
  socket: Udp,
  length: Int,
  timeout: net.Timeout,
) -> Result(#(net.IpAddress, net.Port, BitArray), UdpError)

@external(erlang, "udp_ffi", "controlling_process")
fn udp_controlling_process_(
  socket: Udp,
  pid: process.Pid,
) -> Result(Nil, UdpError)

@external(erlang, "udp_ffi", "close")
fn udp_close_(socket: Udp) -> Nil

@external(erlang, "inet_ffi", "port")
fn inet_port_(socket: Udp) -> Result(Int, Nil)
