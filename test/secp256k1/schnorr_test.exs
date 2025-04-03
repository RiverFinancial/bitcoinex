defmodule Bitcoinex.Secp256k1.SchnorrTest do
  use ExUnit.Case
  doctest Bitcoinex.Secp256k1.Schnorr

  alias Bitcoinex.Utils
  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{Params, Point, PrivateKey, Schnorr, Signature}
  # alias Bitcoinex.Secp256k1.{PrivateKey}

  @n Params.curve().n

  # BIP340 official test vectors:
  # https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
  @schnorr_signatures_with_secrets [
    %{
      secret: 3,
      pubkey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
      aux_rand: 0x0000000000000000000000000000000000000000000000000000000000000000,
      message: 0x0000000000000000000000000000000000000000000000000000000000000000,
      signature:
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
      result: true
    },
    %{
      secret: 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,
      pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
      aux_rand: 0x0000000000000000000000000000000000000000000000000000000000000001,
      message: 0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
      signature:
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
      result: true
    },
    %{
      secret: 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9,
      pubkey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
      aux_rand: 0xC87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906,
      message: 0x7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C,
      signature:
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
      result: true
    },
    # test fails if msg is reduced mod p or n
    %{
      secret: 0x0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710,
      pubkey: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
      aux_rand: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
      message: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
      signature:
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
      result: true
    }
  ]

  # BIP340 official test vectors:
  # https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
  @schnorr_signatures_no_secrets @schnorr_signatures_with_secrets ++
                                   [
                                     %{
                                       pubkey:
                                         "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
                                       message:
                                         0x4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703,
                                       signature:
                                         "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
                                       result: true
                                     },
                                     %{
                                       pubkey:
                                         "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
                                       message:
                                         0x4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703,
                                       signature:
                                         "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                                       result: false
                                     },
                                     %{
                                       pubkey:
                                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
                                       message:
                                         0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89,
                                       signature:
                                         "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                                       result: false
                                     }
                                   ]

  def get_rand_values_for_encrypted_sig() do
    sk_int = :rand.uniform(@n - 1)
    {:ok, sk} = PrivateKey.new(sk_int)
    sk = Secp256k1.force_even_y(sk)
    pk = PrivateKey.to_point(sk)

    # tweak
    tweak_int = :rand.uniform(@n - 1)
    {:ok, tweak} = PrivateKey.new(tweak_int)
    tweak_point = PrivateKey.to_point(tweak)

    msg = :rand.uniform(@n - 1) |> :binary.encode_unsigned()
    z = Utils.double_sha256(msg) |> :binary.decode_unsigned()

    aux = :rand.uniform(@n - 1)

    {sk, pk, tweak, tweak_point, z, aux}
  end

  describe "sign/3" do
    test "sign" do
      for t <- @schnorr_signatures_with_secrets do
        {:ok, sk} = PrivateKey.new(t.secret)

        {:ok, sig} = Schnorr.sign(sk, t.message, t.aux_rand)
        result = Signature.serialize_signature(sig) |> Base.encode16(case: :upper) == t.signature
        assert result == t.result
      end
    end

    test "sign & verify" do
      for t <- @schnorr_signatures_with_secrets do
        {:ok, sk} = PrivateKey.new(t.secret)
        {:ok, pubkey} = Point.lift_x(t.pubkey)

        {:ok, sig} = Schnorr.sign(sk, t.message, t.aux_rand)
        result = Schnorr.verify_signature(pubkey, t.message, sig)
        assert result == t.result
      end
    end
  end

  describe "verify_signature/3" do
    test "verify_signature" do
      for t <- @schnorr_signatures_no_secrets do
        pk_res =
          t.pubkey
          |> Utils.hex_to_bin()
          |> Point.lift_x()

        sig_res =
          t.signature
          |> Base.decode16!(case: :upper)
          |> Signature.parse_signature()

        case {pk_res, sig_res} do
          {{:ok, pubkey}, {:ok, sig}} ->
            assert Schnorr.verify_signature(pubkey, t.message, sig) == t.result

          _ ->
            assert !t.result
        end
      end
    end
  end

  describe "fuzz test signing" do
    setup do
      privkey = Secp256k1.force_even_y(%PrivateKey{d: 123_414_253_234_542_345_423_623})
      pubkey = PrivateKey.to_point(privkey)
      {:ok, privkey: privkey, pubkey: pubkey}
    end

    test "successfully sign a large number of random messages", %{
      privkey: privkey,
      pubkey: pubkey
    } do
      aux =
        32
        |> :crypto.strong_rand_bytes()
        |> :binary.decode_unsigned()

      for _ <- 1..1000 do
        z =
          32
          |> :crypto.strong_rand_bytes()
          |> :binary.decode_unsigned()

        {:ok, sig} = Schnorr.sign(privkey, z, aux)
        assert Schnorr.verify_signature(pubkey, z, sig)
      end
    end

    test "successfully sign a message with a large number of aux inputs", %{
      privkey: privkey,
      pubkey: pubkey
    } do
      z =
        32
        |> :crypto.strong_rand_bytes()
        |> :binary.decode_unsigned()

      for _ <- 1..1000 do
        aux =
          32
          |> :crypto.strong_rand_bytes()
          |> :binary.decode_unsigned()

        {:ok, sig} = Schnorr.sign(privkey, z, aux)
        assert Schnorr.verify_signature(pubkey, z, sig)
      end
    end

    test "successfully sign a message with a large number of keys" do
      z =
        32
        |> :crypto.strong_rand_bytes()
        |> :binary.decode_unsigned()

      aux =
        32
        |> :crypto.strong_rand_bytes()
        |> :binary.decode_unsigned()

      for _ <- 1..1000 do
        secret =
          32
          |> :crypto.strong_rand_bytes()
          |> :binary.decode_unsigned()

        privkey = Secp256k1.force_even_y(%PrivateKey{d: secret})
        pubkey = PrivateKey.to_point(privkey)
        {:ok, sig} = Schnorr.sign(privkey, z, aux)
        assert Schnorr.verify_signature(pubkey, z, sig)
      end
    end
  end

  describe "encrypted signature testing" do
    test "encrypted_sign/4 and verify_encrypted_signature/5" do
      for _ <- 1..1000 do
        {sk, pk, _tweak, tweak_point, z, aux} = get_rand_values_for_encrypted_sig()

        # create adaptor sig
        {:ok, ut_sig, was_negated} = Schnorr.encrypted_sign(sk, z, aux, tweak_point)
        assert Schnorr.verify_encrypted_signature(ut_sig, pk, z, tweak_point, was_negated)
      end
    end

    test "encrypt & decrypt signature" do
      for _ <- 1..1000 do
        {sk, pk, tweak, tweak_point, z, aux} = get_rand_values_for_encrypted_sig()

        # create adaptor sig
        {:ok, ut_sig, was_negated} = Schnorr.encrypted_sign(sk, z, aux, tweak_point)
        assert Schnorr.verify_encrypted_signature(ut_sig, pk, z, tweak_point, was_negated)

        # decrypt to real Schnorr Signature using tweak
        sig = Schnorr.decrypt_signature(ut_sig, tweak, was_negated)
        # ensure valid Schnorr signature
        assert Schnorr.verify_signature(pk, z, sig)
      end
    end

    test "encrypt & recover descryption key" do
      for _ <- 1..1000 do
        {sk, pk, tweak, tweak_point, z, aux} = get_rand_values_for_encrypted_sig()

        # create adaptor sig
        {:ok, ut_sig, was_negated} = Schnorr.encrypted_sign(sk, z, aux, tweak_point)
        assert Schnorr.verify_encrypted_signature(ut_sig, pk, z, tweak_point, was_negated)

        # decrypt to real Schnorr Signature using tweak
        sig = Schnorr.decrypt_signature(ut_sig, tweak, was_negated)
        # ensure valid Schnorr signature
        assert Schnorr.verify_signature(pk, z, sig)

        recovered_tweak = Schnorr.recover_decryption_key(ut_sig, sig, was_negated)
        assert recovered_tweak == tweak
      end
    end
  end

  describe "signature_point testing" do
    test "signature_point matches sign_with_nonce" do
      for _ <- 0..1000 do
        {sk, pk, nonce, nonce_point, z, _aux} = get_rand_values_for_encrypted_sig()
        sig_pk = Schnorr.calculate_signature_point(nonce_point, pk, :binary.encode_unsigned(z))
        %Signature{s: s} = Schnorr.sign_with_nonce(sk, nonce, z)
        {:ok, sig_sk} = PrivateKey.new(s)
        # ensure that Signature.s is the privkey to the sig_point
        assert PrivateKey.to_point(sig_sk) == sig_pk
      end
    end
  end
end
