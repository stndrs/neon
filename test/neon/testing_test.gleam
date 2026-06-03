import gleam/bit_array
import gleam/erlang/process
import gleam/list
import neon/net
import neon/ssl
import neon/testing

const host = "localhost"

// ---------- RSA ---------- //

pub fn rsa_pkix_test_data_test() {
  let data =
    testing.rsa(2048)
    |> testing.pkix_test_data(host)

  // Server cert data is non-empty
  assert bit_array.byte_size(data.server.cert) > 0
  assert list.is_empty(data.server.cacerts) == False
  assert list.all(data.server.cacerts, fn(ca) { bit_array.byte_size(ca) > 0 })

  // Client cert data is non-empty
  assert bit_array.byte_size(data.client.cert) > 0
  assert list.is_empty(data.client.cacerts) == False
  assert list.all(data.client.cacerts, fn(ca) { bit_array.byte_size(ca) > 0 })

  // Prove the certs work in an actual TLS handshake
  assert_handshake(data, <<"rsa ok":utf8>>)
}

// ---------- EC ---------- //

pub fn ec_pkix_test_data_test() {
  let data =
    testing.Secp256r1
    |> testing.ec
    |> testing.pkix_test_data(host)

  assert bit_array.byte_size(data.server.cert) > 0
  assert list.is_empty(data.server.cacerts) == False
  assert list.all(data.server.cacerts, fn(ca) { bit_array.byte_size(ca) > 0 })

  assert bit_array.byte_size(data.client.cert) > 0
  assert list.is_empty(data.client.cacerts) == False
  assert list.all(data.client.cacerts, fn(ca) { bit_array.byte_size(ca) > 0 })

  // Prove the certs work in an actual TLS handshake
  assert_handshake(data, <<"ec ok":utf8>>)
}

pub fn ec_secp384r1_test() {
  let data =
    testing.Secp384r1
    |> testing.ec
    |> testing.pkix_test_data(host)

  assert bit_array.byte_size(data.server.cert) > 0
  assert list.is_empty(data.server.cacerts) == False

  assert_handshake(data, <<"ec384 ok":utf8>>)
}

pub fn ec_secp521r1_test() {
  let data =
    testing.Secp521r1
    |> testing.ec
    |> testing.pkix_test_data(host)

  assert bit_array.byte_size(data.server.cert) > 0
  assert list.is_empty(data.server.cacerts) == False

  assert_handshake(data, <<"ec521 ok":utf8>>)
}

// ---------- helpers ---------- //

fn assert_handshake(data: testing.PkixTestData, payload: BitArray) {
  let size = bit_array.byte_size(payload)

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
      assert Ok(Nil) == ssl.send(server_ssl, payload)
      process.send(test_subject, Nil)
    })

  let host = net.hostname(host)

  let assert Ok(client_ssl) =
    ssl.new(host, listener_port)
    |> ssl.verify_none
    |> ssl.connect

  let assert Ok(timeout) = net.timeout(5000)
  let assert Ok(received) = ssl.receive(client_ssl, size, timeout)
  assert received == payload

  let assert Ok(_) = process.receive(test_subject, 5000)
}
