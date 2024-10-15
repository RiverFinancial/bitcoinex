alias Bitcoinex.Secp256k1
alias Bitcoinex.Secp256k1.{Math, PrivateKey, Point, Schnorr, Signature}
alias Bitcoinex.Utils

to_hex = fn i -> "0x" <> Integer.to_string(i, 16) end

write_row = fn file, sk, pk, tw, t_point, z, aux, ut_sig, tw_sig, err, is_tweaked_s_even, is_tweaked_s_ooo -> IO.binwrite(file,
to_hex.(sk.d) <> "," <> Point.x_hex(pk) <> "," <> to_hex.(tw.d) <> ","
<> Point.x_hex(t_point) <> "," <> to_hex.(z) <> "," <>  to_hex.(aux) <> ","
<>  Signature.to_hex(ut_sig) <> "," <> Signature.to_hex(tw_sig) <> ","
<> err <> "," <> to_string(is_tweaked_s_even) <> "," <> to_string(is_tweaked_s_ooo) <> "\n")
end

order_n = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141

{:ok, good_file} = File.open("schnorr_adaptor_test_vectors-good.csv", [:write])
{:ok, bad_file} = File.open("schnorr_adaptor_test_vectors-bad.csv", [:write])

IO.binwrite(good_file, "private_key,public_key,tweak_secret,tweak_point,message_hash,aux_rand,untweaked_adaptor_signature,tweaked_signature,is_tweaked_s_even\n")
IO.binwrite(bad_file, "private_key,public_key,tweak_secret,tweak_point,message_hash,aux_rand,untweaked_adaptor_signature,tweaked_signature,is_tweaked_s_even\n")

for _ <- 1..50 do
  ski = :rand.uniform(order_n-1)
  {:ok, sk0} = PrivateKey.new(ski)
  sk = Secp256k1.force_even_y(sk0)
  pk = PrivateKey.to_point(sk)

  # tweak
  ti = :rand.uniform(order_n-1)
  {:ok, tw} = PrivateKey.new(ti)
  tw = Secp256k1.force_even_y(tw)
  tw_point = PrivateKey.to_point(tw)

  msg =
    :rand.uniform(order_n-1)
    |> :binary.encode_unsigned()
  z = Utils.double_sha256(msg) |> :binary.decode_unsigned()

  aux = :rand.uniform(order_n-1)

  # create adaptor sig
  {:ok, ut_sig, _tw_point} = Schnorr.sign_for_tweak(sk, z, aux, tw_point)
  tw_sig = Schnorr.tweak_signature(ut_sig, tw.d)

  # checks
  tweaked_s = tw.d+ut_sig.s
  is_tweaked_s_ooo = tweaked_s > order_n
  {:ok, tweaked_s} = PrivateKey.new(Math.modulo(tweaked_s, order_n))
  tweaked_forced_s = Secp256k1.force_even_y(tweaked_s)
  is_tweaked_s_even = tweaked_forced_s == tweaked_s

  case Schnorr.verify_signature(pk, z, tw_sig) do
    true ->
      write_row.(good_file, sk, pk, tw, tw_point, z, aux, ut_sig, tw_sig, "", is_tweaked_s_even, is_tweaked_s_ooo)
    {:error, err} ->
      write_row.(bad_file, sk, pk, tw, tw_point, z, aux, ut_sig, tw_sig, err, is_tweaked_s_even, is_tweaked_s_ooo)
    end
end
