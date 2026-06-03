-module(ssl_ffi).

-export([
  start/0,
  stop/0,
  port/1,
  connect/5,
  upgrade/5,
  send/2,
  recv/3,
  shutdown/1,
  close/1,
  listen/2,
  transport_accept/2,
  handshake/5,
  active/1,
  passive/1,
  handle_ssl_message/1,
  controlling_process/2
]).

start() ->
  Resp = ssl:start(),
  normalise(Resp).

stop() ->
  ssl:stop(),
  nil.

port(SslSocket) ->
  Resp = ssl:sockname(SslSocket),
  normalise(Resp).

upgrade(TCPSocket, Host, Verify, MaybeCaCerts, {timeout, Int}) ->
  upgrade(TCPSocket, Host, Verify, MaybeCaCerts, Int);

upgrade(TCPSocket, Host, Verify, MaybeCaCerts, Timeout) ->
  TLSOpts = connect_opts(Host, Verify, MaybeCaCerts),
  Resp = ssl:connect(TCPSocket, TLSOpts, Timeout),
  normalise(Resp).

connect(Host, Port, Verify, MaybeCaCerts, {timeout, Int}) ->
  connect(Host, Port, Verify, MaybeCaCerts, Int);

connect(Host, {port, Port}, Verify, MaybeCaCerts, Timeout) ->
  TLSOpts = connect_opts(Host, Verify, MaybeCaCerts),
  Resp = ssl:connect(Host, Port, TLSOpts, Timeout),
  normalise(Resp).

connect_opts(Host, {verify, verify_none}, _MaybeCaCerts) ->
  [
    binary,
    {packet, raw},
    {active, false},
    {verify, verify_none},
    {server_name_indication, Host}
  ];

connect_opts(Host, {verify, verify_peer}, CaCerts) ->
  Certs = case CaCerts of
    {some, C} -> C;
    none -> public_key:cacerts_get()
  end,

  [
    binary,
    {packet, raw},
    {active, false},
    {verify, verify_peer},
    {cacerts, Certs},
    {server_name_indication, Host},
    {customize_hostname_check, [
      {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
    ]
  }].

active(SslSocket) ->
  case ssl:setopts(SslSocket, [{active, true}]) of
    ok -> {ok, SslSocket};
    Error -> normalise(Error)
  end.

passive(SslSocket) ->
  case ssl:setopts(SslSocket, [{active, false}]) of
    ok -> {ok, SslSocket};
    Error -> normalise(Error)
  end.

controlling_process(SslSocket, Pid) ->
  Res = ssl:controlling_process(SslSocket, Pid),
  case normalise(Res) of
    {error, badarg} -> {error, closed};
    Other -> Other
  end.

shutdown(SslSocket) ->
  Shut = ssl:shutdown(SslSocket, read_write),
  normalise(Shut).

close(SslSocket) ->
  Resp = ssl:close(SslSocket),
  normalise(Resp).

recv(SslSocket, Size, {timeout, Int}) ->
  recv(SslSocket, Size, Int);

recv(SslSocket, Size, Timeout) ->
  Resp = ssl:recv(SslSocket, Size, Timeout),
  normalise(Resp).

send(SslSocket, Packet) ->
  Sent = ssl:send(SslSocket, Packet),
  normalise(Sent).

listen({port, Port}, IpAddress) ->
  {Inet, Address} = ip_address_and_version(IpAddress),

  Options = [
    binary,
    {ip, Address},
    {packet, raw},
    {active, false},
    {reuseaddr, true},
    Inet
  ],
  Resp = ssl:listen(Port, Options),
  normalise(Resp).

transport_accept(ListenSocket, {timeout, Int}) ->
  transport_accept(ListenSocket, Int);

transport_accept(ListenSocket, Timeout) ->
  Resp = ssl:transport_accept(ListenSocket, Timeout),
  normalise(Resp).

handshake(Socket, Cert, Key, MaybeCaCerts, {timeout, Int}) ->
  handshake(Socket, Cert, Key, MaybeCaCerts, Int);

handshake(Socket, Cert, Key, MaybeCaCerts, Timeout) ->
  ErlKey = private_key_to_erl(Key),

  BaseOpts = [
    {cert, Cert},
    {key, ErlKey},
    {verify, verify_none}
  ],

  Opts = case MaybeCaCerts of
    none -> BaseOpts;
    {some, CaCerts} -> [{cacerts, CaCerts} | BaseOpts]
  end,

  Resp = ssl:handshake(Socket, Opts, Timeout),
  normalise(Resp).

private_key_to_erl({rsa_private_key, Der}) -> {'RSAPrivateKey', Der};
private_key_to_erl({ec_private_key, Der}) -> {'ECPrivateKey', Der}.

normalise(ok) -> {ok, nil};
normalise({ok, {_Address, Port}}) -> {ok, {port, Port}};
normalise({ok, SslSocket}) -> {ok, SslSocket};
normalise({ok, SslSocket, _Ext}) -> {ok, SslSocket};
normalise({error, closed}) -> {error, closed};
normalise({error, timeout}) -> {error, timeout};
normalise({error, {tls_alert, {Alert, Description}}}) ->
  Desc = unicode:characters_to_binary(Description),
  {error, {tls_alert, Alert, Desc}};
normalise({error, ssl_not_started}) -> {error, ssl_not_started};
normalise({error, not_owner}) -> {error, not_owner};
normalise({error, badarg}) -> {error, badarg};
normalise({error, Reason}) when is_atom(Reason) ->
  {error, {posix, Reason}};
normalise({error, Reason}) ->
  Formatted = ssl:format_error(Reason),
  Description = unicode:characters_to_binary(Formatted),
  {error, {ssl_error, Description}}.

ip_address_and_version({ipv4_address, A, B, C, D}) ->
  {inet, {A, B, C, D}};
ip_address_and_version({ipv6_address, A, B, C, D, E, F, G, H}) ->
  {inet6, {A, B, C, D, E, F, G, H}}.

handle_ssl_message({ssl, Socket, Data}) ->
  {packet, Socket, Data};
handle_ssl_message({ssl_closed, Socket}) ->
  {socket_closed, Socket};
handle_ssl_message({ssl_error, Socket, Reason}) ->
  {socket_error, Socket, normalise_error(Reason)}.

normalise_error(closed) -> closed;
normalise_error(timeout) -> timeout;
normalise_error({tls_alert, {Alert, Description}}) ->
  Desc = unicode:characters_to_binary(Description),
  {tls_alert, Alert, Desc};
normalise_error(Posix) when is_atom(Posix) -> {posix, Posix};
normalise_error(Reason) ->
  Formatted = ssl:format_error(Reason),
  Description = unicode:characters_to_binary(Formatted),
  {ssl_error, Description}.
