
alias Bitcoinex.Secp256k1
alias Bitcoinex.Secp256k1.{PrivateKey, Schnorr, Signature}

test = %{
  privkey: 0x279D71D68D3EE997019D005BDF703C271001631A7EE12E4C9DAD10C0754912DC,
  pubkey: 0x22c63594ea2c2199e0500cdf6dffecdf878441720789c8dfcfb9af06a96fd1e4,
  tweak_secret: 0xF8EBFDF85A3AF0C337ECB165EF47D565DE15CBCEEB597A243C3D54DF49B703D5,
  tweak_point: 0x6545e169e4d2e940e63207110a9d44dd5d4ca65aeb58e3e566658f62d41bd23f,
  message_hash: 0x5736367EBB12EDC15B0FA75319B46D016F86A0E057B9237240D6185C93596367,
  aux_rand: 0x7E4E37835DDFC6A82A011073DCB779D02F1F5B52A2937B6ADD5B9DA2528FC5C6,
  untweaked_sig: "e2125e2f6d791ce59b604dfc0578a823008a5c86f2f2efbd0de68a4cb19688d817ebac918f08e0078c66a26c664d9f169d66dc54fdd95972e68a69b79797274a",
  tweaked_sig: "320ab814c2e7e2567af8e738ce83e9fdc55ef57933dd52b169bba46fd3516e4c10d7aa89e943d0cac45353d25595747dc0cdcb3d39ea335b62f5600a1117e9de"
}

z = test.message_hash
aux = test.aux_rand

{:ok, t} = PrivateKey.new(test.tweak_secret)
t2 = Secp256k1.force_even_y(t)
t_point = PrivateKey.to_point(t)

{:ok, sk} = PrivateKey.new(test.privkey)
sk2 = Secp256k1.force_even_y(sk)

# use sk2
pk = PrivateKey.to_point(sk2)
{:ok, ut_sig, t_point_} = Schnorr.sign_for_tweak(sk2, z, aux, t_point)
tw_sig = Schnorr.tweak_signature(ut_sig, t.d)
Schnorr.verify_signature(pk, z, tw_sig)
