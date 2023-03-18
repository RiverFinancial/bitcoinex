alias Bitcoinex.Secp256k1
alias Bitcoinex.Secp256k1.{PrivateKey, Point, Schnorr, Signature}
alias Bitcoinex.Utils
# private key
{:ok, sk} = PrivateKey.new(1234123412341234123412341234)
pk = PrivateKey.to_point(sk)

# tweak
{:ok, t} = PrivateKey.new(658393766392737484910002828395)
t = Secp256k1.force_even_y(t)
t_point = PrivateKey.to_point(t)

msg = "tweakin"
z = Utils.double_sha256(msg) |> :binary.decode_unsigned()

aux = 1203948712823749283

# create adaptor sig
{:ok, ut_sig, t_point_} = Schnorr.sign_for_tweak(sk, z, aux, t_point)
t_point_ == t_point

# adaptor sig is not a valid schnorr sig
!Schnorr.verify_signature(pk, z, ut_sig)

# verify adaptor signature
Schnorr.verify_untweaked_signature(pk, z, ut_sig, t_point)

# complete adaptor sig
tw_sig = Schnorr.tweak_signature(ut_sig, t.d)

# complete sig must be valid schnorr sig
Schnorr.verify_signature(pk, z, tw_sig)

# extract tweak
{:ok, tweak} = Schnorr.extract_tweak(pk, z, ut_sig, tw_sig)
tweak == t.d

# extract signature given tweak
{:ok, sig} = Schnorr.extract_tweaked_signature(pk, z, ut_sig, t.d)
sig == tw_sig
