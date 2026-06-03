import gleam/dynamic
import gleam/erlang/atom
import gleam/erlang/charlist.{type Charlist}
import gleam/erlang/process.{type Selector}
import gleam/option.{type Option, None, Some}
import neon/net
import neon/tcp.{type Tcp}

/// An SSL/TLS socket.
pub type Ssl

/// A private key for SSL/TLS server authentication.
pub opaque type PrivateKey {
  /// An RSA private key in DER-encoded binary format.
  RsaPrivateKey(BitArray)
  /// An EC private key in DER-encoded binary format.
  EcPrivateKey(BitArray)
}

/// Creates an RSA private key from a DER-encoded binary.
pub fn rsa_private_key(key: BitArray) -> PrivateKey {
  RsaPrivateKey(key)
}

/// Creates an EC private key from a DER-encoded binary.
pub fn ec_private_key(key: BitArray) -> PrivateKey {
  EcPrivateKey(key)
}

/// TLS alert descriptions as defined in the [Erlang ssl module documentation][1].
///
/// [1]: https://www.erlang.org/doc/apps/ssl/ssl.html#t:tls_alert/0
pub type TlsAlert {
  CloseNotify
  UnexpectedMessage
  BadRecordMac
  RecordOverflow
  HandshakeFailure
  BadCertificate
  UnsupportedCertificate
  CertificateRevoked
  CertificateExpired
  CertificateUnknown
  IllegalParameter
  UnknownCa
  AccessDenied
  DecodeError
  DecryptError
  ExportRestriction
  ProtocolVersion
  InsufficientSecurity
  InternalError
  InappropriateFallback
  UserCanceled
  NoRenegotiation
  UnsupportedExtension
  CertificateUnobtainable
  UnrecognizedName
  BadCertificateStatusResponse
  BadCertificateHashValue
  UnknownPskIdentity
  NoApplicationProtocol
}

/// Errors that can occur during SSL/TLS operations.
pub type SslError {
  /// The connection was closed.
  Closed
  /// The operation timed out.
  Timeout
  /// The specified PID is not socket's owner.
  NotOwner
  /// A POSIX error.
  Posix(net.Posix)
  /// A TLS alert.
  TlsAlert(TlsAlert, String)
  /// A generic SSL error with a description.
  SslError(String)
  /// The SSL application has not been started. Call `start` first.
  SslNotStarted
}

/// Messages received from an SSL socket in active mode.
///
/// Use `select` to register handlers for these messages on a `Selector`.
pub type SslMessage {
  /// Data received from the socket.
  Packet(Ssl, BitArray)
  /// The socket was closed by the remote peer.
  SocketClosed(Ssl)
  /// An error occurred on the socket.
  SocketError(Ssl, SslError)
}

type VerifyValue {
  VerifyNone
  VerifyPeer
}

type Verify {
  Verify(VerifyValue)
}

type Connect {
  Open(host: String, port: net.Port)
  Upgrade(socket: Tcp, host: String)
}

/// Options for establishing an SSL/TLS connection.
pub opaque type ConnectOptions {
  ConnectOptions(
    connect: Connect,
    verify: Verify,
    cacerts: Option(List(BitArray)),
    timeout: net.Timeout,
  )
}

/// Creates connection options for a fresh SSL/TLS connection to the given
/// host and port.
///
/// Defaults to `verify_peer` and an infinite timeout.
pub fn new(host: String, port: net.Port) -> ConnectOptions {
  let connect = Open(host:, port:)

  ConnectOptions(
    connect:,
    verify: Verify(VerifyPeer),
    cacerts: None,
    timeout: net.infinity,
  )
}

/// Creates connection options to upgrade an existing TCP socket to SSL/TLS.
///
/// The `host` is used for Server Name Indication (SNI). Defaults to
/// `verify_peer` and an infinite timeout.
pub fn from_tcp(socket: Tcp, host: String) -> ConnectOptions {
  let connect = Upgrade(socket:, host:)

  ConnectOptions(
    connect:,
    verify: Verify(VerifyPeer),
    cacerts: None,
    timeout: net.infinity,
  )
}

/// Disables certificate verification.
///
/// This is insecure and should only be used for testing or when connecting
/// to hosts with self-signed certificates.
pub fn verify_none(opts: ConnectOptions) -> ConnectOptions {
  ConnectOptions(..opts, verify: Verify(VerifyNone))
}

/// Enables certificate verification against the system CA store.
///
/// This is the default.
pub fn verify_peer(opts: ConnectOptions) -> ConnectOptions {
  ConnectOptions(..opts, verify: Verify(VerifyPeer))
}

/// Sets the CA certificates to use for peer verification.
///
/// When set, these certificates are used instead of the system CA store.
/// Only has an effect when `verify_peer` is enabled.
pub fn connect_cacerts(
  opts: ConnectOptions,
  certs: List(BitArray),
) -> ConnectOptions {
  ConnectOptions(..opts, cacerts: Some(certs))
}

/// Sets the connection timeout.
pub fn timeout(opts: ConnectOptions, timeout: net.Timeout) -> ConnectOptions {
  ConnectOptions(..opts, timeout:)
}

/// Establishes an SSL/TLS connection using the given options.
///
/// This either opens a new connection or upgrades an existing TCP socket,
/// depending on whether `new` or `from_tcp` was used to create the options.
///
/// `start` must be called before this function.
pub fn connect(opts: ConnectOptions) -> Result(Ssl, SslError) {
  case opts.connect {
    Open(host:, port:) ->
      host
      |> charlist.from_string
      |> ssl_connect_(port, opts.verify, opts.cacerts, opts.timeout)
    Upgrade(socket:, host:) -> {
      let host = charlist.from_string(host)

      ssl_upgrade_(socket, host, opts.verify, opts.cacerts, opts.timeout)
    }
  }
}

/// Sends data over an SSL/TLS socket.
pub fn send(socket: Ssl, payload: BitArray) -> Result(Nil, SslError) {
  ssl_send_(socket, payload)
}

/// Receives data from an SSL/TLS socket.
///
/// The `length` parameter specifies the number of bytes to receive. Use `0`
/// to receive whatever data is available. Must be non-negative.
pub fn receive(
  socket: Ssl,
  length: Int,
  timeout: net.Timeout,
) -> Result(BitArray, SslError) {
  case length >= 0 {
    True -> ssl_receive_(socket, length, timeout)
    False -> Error(SslError("Length must be non-negative"))
  }
}

/// Sets the socket to active mode.
///
/// In active mode, incoming data is delivered as messages to the socket
/// owner's mailbox. Use `select` to handle these messages.
pub fn active(socket: Ssl) -> Result(Ssl, SslError) {
  ssl_active_(socket)
}

/// Sets the socket to passive mode.
///
/// In passive mode, data must be read explicitly using `receive`.
pub fn passive(socket: Ssl) -> Result(Ssl, SslError) {
  ssl_passive_(socket)
}

/// Change the controlling process (owner) of a socket.
///
/// The controlling process is the process that the socket sends messages to.
pub fn controlling_process(
  socket: Ssl,
  pid: process.Pid,
) -> Result(Nil, SslError) {
  ssl_controlling_process_(socket, pid)
}

/// Adds SSL message handlers to a selector for use with active mode sockets.
///
/// In active mode, incoming data, close notifications, and errors are
/// delivered as messages to the socket owner's mailbox. Use this function
/// to register handlers for these messages on a `Selector`.
pub fn select(selector: Selector(t), mapper: fn(SslMessage) -> t) -> Selector(t) {
  let map = fn(msg) { mapper(handle_ssl_message_(msg)) }
  selector
  |> process.select_record(tag: atom.create("ssl"), fields: 2, mapping: map)
  |> process.select_record(
    tag: atom.create("ssl_closed"),
    fields: 1,
    mapping: map,
  )
  |> process.select_record(
    tag: atom.create("ssl_error"),
    fields: 2,
    mapping: map,
  )
}

/// Shuts down the SSL/TLS connection for both reading and writing.
pub fn shutdown(socket: Ssl) -> Result(Nil, SslError) {
  ssl_shutdown_(socket)
}

/// Closes an SSL/TLS socket.
pub fn close(socket: Ssl) -> Result(Nil, SslError) {
  ssl_close_(socket)
}

/// Starts the SSL application and its dependencies.
///
/// Must be called before any SSL/TLS operations. This function is
/// idempotent and can safely be called multiple times.
@external(erlang, "ssl_ffi", "start")
pub fn start() -> Result(Nil, SslError)

/// Stops the SSL application.
///
/// After calling this, SSL/TLS operations will fail with `SslNotStarted`
/// until `start` is called again.
@external(erlang, "ssl_ffi", "stop")
pub fn stop() -> Nil

/// Returns the port number assigned to an SSL socket by the operating system.
pub fn port(socket: Ssl) -> Result(net.Port, SslError) {
  ssl_port_(socket)
}

/// Options for performing a server-side TLS handshake.
///
/// Create with `handshake_options`, then optionally configure with
/// `cacerts` and `handshake_timeout` before passing to `handshake`.
pub opaque type HandshakeOptions {
  HandshakeOptions(
    cert: BitArray,
    key: PrivateKey,
    cacerts: Option(List(BitArray)),
    timeout: net.Timeout,
  )
}

/// Creates handshake options with the given certificate and private key.
///
/// The certificate should be a DER-encoded binary. Defaults to no CA
/// certificates and an infinite timeout.
pub fn handshake_options(cert: BitArray, key: PrivateKey) -> HandshakeOptions {
  HandshakeOptions(cert:, key:, cacerts: None, timeout: net.infinity)
}

/// Sets the CA certificates for client certificate verification.
pub fn handshake_cacerts(
  opts: HandshakeOptions,
  certs: List(BitArray),
) -> HandshakeOptions {
  HandshakeOptions(..opts, cacerts: Some(certs))
}

/// Sets the handshake timeout.
pub fn handshake_timeout(
  opts: HandshakeOptions,
  timeout: net.Timeout,
) -> HandshakeOptions {
  HandshakeOptions(..opts, timeout:)
}

/// Creates an SSL listen socket bound to the given port and IP address.
pub fn listen(
  port: net.Port,
  ip_address: net.IpAddress,
) -> Result(Ssl, SslError) {
  ssl_listen_(port, ip_address)
}

/// Accepts an incoming connection on an SSL listen socket.
///
/// Returns a transport socket that has not yet completed the TLS
/// handshake. Call `handshake` to complete the TLS negotiation.
pub fn accept(socket: Ssl, timeout: net.Timeout) -> Result(Ssl, SslError) {
  ssl_transport_accept_(socket, timeout)
}

/// Performs the server-side TLS handshake on a transport socket
/// returned by `accept`.
///
/// `start` must be called before this function.
pub fn handshake(socket: Ssl, opts: HandshakeOptions) -> Result(Ssl, SslError) {
  ssl_handshake_(socket, opts.cert, opts.key, opts.cacerts, opts.timeout)
}

/// Performs a server-side TLS handshake on a raw TCP socket.
///
/// This is the server-side counterpart to `from_tcp` and is used for
/// START-TLS upgrades where an existing TCP connection is promoted to TLS.
///
/// `start` must be called before this function.
pub fn handshake_from_tcp(
  socket: Tcp,
  opts: HandshakeOptions,
) -> Result(Ssl, SslError) {
  ssl_handshake_tcp_(socket, opts.cert, opts.key, opts.cacerts, opts.timeout)
}

@external(erlang, "ssl_ffi", "upgrade")
fn ssl_upgrade_(
  socket: Tcp,
  host: Charlist,
  verify: Verify,
  cacerts: Option(List(BitArray)),
  timeout: net.Timeout,
) -> Result(Ssl, SslError)

@external(erlang, "ssl_ffi", "active")
fn ssl_active_(socket: Ssl) -> Result(Ssl, SslError)

@external(erlang, "ssl_ffi", "passive")
fn ssl_passive_(socket: Ssl) -> Result(Ssl, SslError)

@external(erlang, "ssl_ffi", "handle_ssl_message")
fn handle_ssl_message_(message: dynamic.Dynamic) -> SslMessage

@external(erlang, "ssl_ffi", "connect")
fn ssl_connect_(
  host: Charlist,
  port: net.Port,
  verify: Verify,
  cacerts: Option(List(BitArray)),
  timeout: net.Timeout,
) -> Result(Ssl, SslError)

@external(erlang, "ssl_ffi", "send")
fn ssl_send_(socket: Ssl, payload: BitArray) -> Result(Nil, SslError)

@external(erlang, "ssl_ffi", "recv")
fn ssl_receive_(
  socket: Ssl,
  length: Int,
  timeout: net.Timeout,
) -> Result(BitArray, SslError)

@external(erlang, "ssl_ffi", "shutdown")
fn ssl_shutdown_(socket: Ssl) -> Result(Nil, SslError)

@external(erlang, "ssl_ffi", "close")
fn ssl_close_(socket: Ssl) -> Result(Nil, SslError)

@external(erlang, "ssl_ffi", "port")
fn ssl_port_(socket: Ssl) -> Result(net.Port, SslError)

@external(erlang, "ssl_ffi", "listen")
fn ssl_listen_(
  port: net.Port,
  ip_address: net.IpAddress,
) -> Result(Ssl, SslError)

@external(erlang, "ssl_ffi", "transport_accept")
fn ssl_transport_accept_(
  socket: Ssl,
  timeout: net.Timeout,
) -> Result(Ssl, SslError)

@external(erlang, "ssl_ffi", "handshake")
fn ssl_handshake_(
  socket: Ssl,
  cert: BitArray,
  key: PrivateKey,
  cacerts: Option(List(BitArray)),
  timeout: net.Timeout,
) -> Result(Ssl, SslError)

@external(erlang, "ssl_ffi", "handshake")
fn ssl_handshake_tcp_(
  socket: Tcp,
  cert: BitArray,
  key: PrivateKey,
  cacerts: Option(List(BitArray)),
  timeout: net.Timeout,
) -> Result(Ssl, SslError)

@external(erlang, "ssl_ffi", "controlling_process")
fn ssl_controlling_process_(
  socket: Ssl,
  pid: process.Pid,
) -> Result(Nil, SslError)
