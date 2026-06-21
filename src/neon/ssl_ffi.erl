-module(ssl_ffi).

-export([
  start/0,
  stop/0,
  port/1,
  connect/6,
  upgrade/6,
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

upgrade(TCPSocket, Address, Verify, MaybeCaCerts, MaybeIdentity, {timeout, Int}) ->
  upgrade(TCPSocket, Address, Verify, MaybeCaCerts, MaybeIdentity, Int);

upgrade(TCPSocket, Address, Verify, MaybeCaCerts, MaybeIdentity, Timeout) ->
  {_Addr, SNI} = address_with_sni(Address),

  TLSOpts = connect_opts(Verify, MaybeCaCerts, MaybeIdentity, SNI),
  TLSOpts1 = [SNI | TLSOpts],

  Resp = ssl:connect(TCPSocket, TLSOpts1, Timeout),
  normalise(Resp).

connect(Address, Port, Verify, MaybeCaCerts, MaybeIdentity, {timeout, Int}) ->
  connect(Address, Port, Verify, MaybeCaCerts, MaybeIdentity, Int);

connect(Address, {port, Port}, Verify, MaybeCaCerts, MaybeIdentity, Timeout) ->
  {Addr, SNI} = address_with_sni(Address),

  TLSOpts = connect_opts(Verify, MaybeCaCerts, MaybeIdentity, SNI),
  TLSOpts1 = [SNI | TLSOpts],

  Resp = ssl:connect(Addr, Port, TLSOpts1, Timeout),
  normalise(Resp).

connect_opts({verify, verify_none}, _MaybeCaCerts, MaybeIdentity, _SNI) ->
  Base = [
    binary,
    {packet, raw},
    {active, false},
    {verify, verify_none}
  ],
  maybe_client_identity(MaybeIdentity, Base);

connect_opts({verify, verify_peer}, CaCerts, MaybeIdentity, SNI) ->
  Certs = case CaCerts of
    {some, C} -> C;
    none -> public_key:cacerts_get()
  end,

  Base = [
    binary,
    {packet, raw},
    {active, false},
    {verify, verify_peer},
    {cacerts, Certs}
  ],

  Base1 = case SNI of
    {server_name_indication, disable} -> Base;
    {server_name_indication, _Host} ->
      [{customize_hostname_check, [
          {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
      ]} | Base]
  end,
  maybe_client_identity(MaybeIdentity, Base1).

maybe_client_identity(none, Opts) -> Opts;
maybe_client_identity({some, {Cert, Key}}, Opts) ->
  [{cert, Cert}, {key, private_key_to_erl(Key)} | Opts].

address_with_sni({hostname, Hostname}) ->
  Host = unicode:characters_to_list(Hostname),
  {Host, {server_name_indication, Host}};

address_with_sni({ip_address, {ipv4_address, A, B, C, D}}) ->
  {{A, B, C, D}, {server_name_indication, disable}};

address_with_sni({ip_address, {ipv6_address, A, B, C, D, E, F, G, H}}) ->
  {{A, B, C, D, E, F, G, H}, {server_name_indication, disable}}.

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
  case erlang:is_process_alive(Pid) of
    false -> {error, invalid_pid};
    true ->
      Res = ssl:controlling_process(SslSocket, Pid),
      normalise(Res)
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
  try ssl:transport_accept(ListenSocket, Timeout) of
    Resp -> normalise(Resp)
  catch
    error:function_clause -> {error, {ssl_error, <<"invalid socket">>}};
    error:badarg -> {error, {ssl_error, <<"invalid socket">>}}
  end.

handshake(Socket, Cert, Key, MaybeCaCerts, {timeout, Int}) ->
  handshake(Socket, Cert, Key, MaybeCaCerts, Int);

handshake(Socket, Cert, Key, MaybeCaCerts, Timeout) ->
  ErlKey = private_key_to_erl(Key),

  BaseOpts = [
    {cert, Cert},
    {key, ErlKey}
  ],

  Opts = case MaybeCaCerts of
    none -> [{verify, verify_none} | BaseOpts];
    {some, CaCerts} ->
      [
        {verify, verify_peer},
        {fail_if_no_peer_cert, true},
        {cacerts, CaCerts}
        | BaseOpts
      ]
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
