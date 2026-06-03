-module(udp_ffi).

-export([
  open/3,
  connect/3,
  send/2,
  recv/3,
  close/1,
  controlling_process/2
]).

open({port, Port}, MaybeIpAddress, IpVersion) ->
  case MaybeIpAddress of
    none ->
      Inet = ip_version_to_inet(IpVersion),
      Opts = [binary, {active, false}, Inet],
      normalise(gen_udp:open(Port, Opts));
    {some, Addr} ->
      {Inet, Tuple} = ip_address_and_version(Addr),
      Opts = [binary, {active, false}, {ip, Tuple}, Inet],
      normalise(gen_udp:open(Port, Opts))
  end.

connect(UdpSocket, Address, {port, Port}) ->
  Addr = case Address of
    {hostname, Hostname} -> unicode:characters_to_list(Hostname);
    {ip_address, {ipv4_address, A, B, C, D}} -> {A, B, C, D};
    {ip_address, {ipv6_address, A, B, C, D, E, F, G, H}} -> {A, B, C, D, E, F, G, H}
  end,
  Resp = gen_udp:connect(UdpSocket, Addr, Port),
  normalise(Resp).

send(UdpSocket, Packet) ->
  Resp = gen_udp:send(UdpSocket, Packet),
  normalise(Resp).

recv(UdpSocket, Length, {timeout, Int}) ->
  recv(UdpSocket, Length, Int);

recv(UdpSocket, Length, Timeout) ->
  Resp = gen_udp:recv(UdpSocket, Length, Timeout),
  normalise(Resp).

close(UdpSocket) ->
  gen_udp:close(UdpSocket),
  nil.

controlling_process(UdpSocket, Pid) ->
  try gen_udp:controlling_process(UdpSocket, Pid) of
    Res ->
      case normalise(Res) of
        {error, badarg} ->
          case erlang:is_process_alive(Pid) of
            false -> {error, {udp_error, <<"invalid pid">>}};
            true  -> {error, closed}
          end;
        Other -> Other
      end
  catch
    error:{badmatch, {error, einval}} -> {error, closed}
  end.

normalise(ok) -> {ok, nil};
normalise({ok, {Address, Port, _, Packet}}) ->
  {ok, {normalise_ip_address(Address), {port, Port}, Packet}};
normalise({ok, {Address, Port, Packet}}) ->
  {ok, {normalise_ip_address(Address), {port, Port}, Packet}};
normalise({ok, UdpSocket}) -> {ok, UdpSocket};
normalise({error, badarg} = E) -> E;
normalise({error, closed} = E) -> E;
normalise({error, timeout} = E) -> E;
normalise({error, system_limit} = E) -> E;
normalise({error, Posix}) -> {error, {posix, Posix}}.

normalise_ip_address({A, B, C, D}) ->
  {ipv4_address, A, B, C, D};
normalise_ip_address({A, B, C, D, E, F, G, H}) ->
  {ipv6_address, A, B, C, D, E, F, G, H}.

ip_address_and_version({ipv4_address, A, B, C, D}) ->
  {inet, {A, B, C, D}};
ip_address_and_version({ipv6_address, A, B, C, D, E, F, G, H}) ->
  {inet6, {A, B, C, D, E, F, G, H}}.

ip_version_to_inet(ipv6) -> inet6;
ip_version_to_inet(ipv4) -> inet.
