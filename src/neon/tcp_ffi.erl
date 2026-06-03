-module(tcp_ffi).

-export([
  active/1,
  passive/1,
  handle_tcp_message/1,
  accept/2,
  close/1,
  listen/2,
  connect/4,
  send/2,
  recv/3,
  shutdown/1,
  controlling_process/2
]).

connect(Address, Port, IpVersion, {timeout, Int}) ->
  connect(Address, Port, IpVersion, Int);

connect(Address, {port, Port}, IpVersion, Timeout) ->
  Inet = ip_version_to_inet(IpVersion),

  Addr = case Address of
    {hostname, Hostname} -> unicode:characters_to_list(Hostname);
    {ip_address, {ipv4_address, A, B, C, D}} -> {A, B, C, D};
    {ip_address, {ipv6_address, A, B, C, D, E, F, G, H}} -> {A, B, C, D, E, F, G, H}
  end,

  Opts = [
    binary,
    {packet, raw},
    {active, false},
    Inet
  ],

  Resp = gen_tcp:connect(Addr, Port, Opts, Timeout),
  normalise(Resp).

ip_version_to_inet(ipv6) -> inet6;
ip_version_to_inet(ipv4) -> inet.

active(TcpSocket) ->
  case inet:setopts(TcpSocket, [{active, true}]) of
    ok -> {ok, TcpSocket};
    Error -> normalise(Error)
  end.

passive(TcpSocket) ->
  case inet:setopts(TcpSocket, [{active, false}]) of
    ok -> {ok, TcpSocket};
    Error -> normalise(Error)
  end.

controlling_process(TcpSocket, Pid) ->
  Res = gen_tcp:controlling_process(TcpSocket, Pid),
  case normalise(Res) of
    %% Pid will always be valid thanks to Gleam type safety.
    %% We just need to handle a case where TcpSocket is closed and
    %% the function returns `{error, badarg}` instead of `{error, closed}`.
    {error, badarg} -> {error, closed};
    Other -> Other
  end.

shutdown(TcpSocket) ->
  Shut = gen_tcp:shutdown(TcpSocket, read_write),
  normalise(Shut).

recv(TcpSocket, Size, {timeout, Int}) ->
  recv(TcpSocket, Size, Int);

recv(TcpSocket, Size, Timeout) ->
  Resp = gen_tcp:recv(TcpSocket, Size, Timeout),
  normalise(Resp).

send(TcpSocket, Packet) ->
  Sent = gen_tcp:send(TcpSocket, Packet),
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
  Resp = gen_tcp:listen(Port, Options),
  normalise(Resp).

ip_address_and_version({ipv4_address, A, B, C, D}) ->
  {inet, {A, B, C, D}};
ip_address_and_version({ipv6_address, A, B, C, D, E, F, G, H}) ->
  {inet6, {A, B, C, D, E, F, G, H}}.

accept(TcpSocket, {timeout, Int}) ->
  accept(TcpSocket, Int);

accept(TcpSocket, Timeout) ->
  Resp = gen_tcp:accept(TcpSocket, Timeout),
  normalise(Resp).

close(TcpSocket) ->
  gen_tcp:close(TcpSocket),
  nil.

normalise(ok) -> {ok, nil};
normalise({ok, TcpSocket}) -> {ok, TcpSocket};
normalise({error, closed} = E) -> E;
normalise({error, timeout} = E) -> E;
normalise({error, system_limit} = E) -> E;
normalise({error, not_owner}) -> {error, not_owner};
normalise({error, badarg}) -> {error, badarg};
normalise({error, {timeout, _}}) -> {error, timeout};
normalise({error, Posix}) -> {error, {posix, Posix}}.

handle_tcp_message({tcp, Socket, Data}) ->
  {packet, Socket, Data};
handle_tcp_message({tcp_closed, Socket}) ->
  {socket_closed, Socket};
handle_tcp_message({tcp_error, Socket, Reason}) ->
  {socket_error, Socket, normalise_error(Reason)}.

normalise_error(closed) -> closed;
normalise_error(timeout) -> timeout;
normalise_error(system_limit) -> system_limit;
normalise_error(Posix) -> {posix, Posix}.
