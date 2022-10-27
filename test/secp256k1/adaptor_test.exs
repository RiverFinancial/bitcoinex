defmodule Bitcoinex.Secp256k1.SchnorrTest do
  use ExUnit.Case

  alias Bitcoinex.Secp256k1
  alias Bitcoinex.Secp256k1.{PrivateKey, Schnorr, Signature}


  @schnorr_adaptor_signatures [
    %{
      privkey: 0x279D71D68D3EE997019D005BDF703C271001631A7EE12E4C9DAD10C0754912DC,
      pubkey: 0x22c63594ea2c2199e0500cdf6dffecdf878441720789c8dfcfb9af06a96fd1e4,
      tweak_secret: 0xF8EBFDF85A3AF0C337ECB165EF47D565DE15CBCEEB597A243C3D54DF49B703D5,
      tweak_point: 0x6545e169e4d2e940e63207110a9d44dd5d4ca65aeb58e3e566658f62d41bd23f,
      message_hash: 0x5736367EBB12EDC15B0FA75319B46D016F86A0E057B9237240D6185C93596367,
      aux_rand: 0x7E4E37835DDFC6A82A011073DCB779D02F1F5B52A2937B6ADD5B9DA2528FC5C6,
      untweaked_sig: "e2125e2f6d791ce59b604dfc0578a823008a5c86f2f2efbd0de68a4cb19688d817ebac918f08e0078c66a26c664d9f169d66dc54fdd95972e68a69b79797274a",
      tweaked_sig: "320ab814c2e7e2567af8e738ce83e9fdc55ef57933dd52b169bba46fd3516e4c10d7aa89e943d0cac45353d25595747dc0cdcb3d39ea335b62f5600a1117e9de"
    },
    %{
      privkey: 0x6F0B8C685BEB787F3121851AC13DAD9549C235217C5F578D9E7BE3B3845D8773,
      pubkey: 0x825fa6ec886022247b7b98d24d47a6f03d3a47f2fa3916a244eba7114ea94fa1,
      tweak_secret: 0x76D2C1FE7E575063C8888D935645973AC3AE1FFD1C97F25D14F7567657D7F748,
      tweak_point: 0xb99378d7cf782cf6ff265ef8e3ba447b36da89224c0682ca61cc9916a4fec4bf,
      message_hash: 0xA193926FAFF8CE363937D8655892E60D45661C5FC510BC711E4B5049A6B4DD30,
      aux_rand: 0x76C66B394932DC5704EC0FB4CE4D76D388707396AC64D9C35BFC081F11D51124,
      untweaked_sig: "864897cd95c22dda7fce0435fe365c658118e52d578ba77c25d1f1e63ff3cd0916b38c325759c310e467a0ec026d8362b2f5155adb19a17eb06a5c661b039be1",
      tweaked_sig: "e277ad505af9e82abcb122c3df410459494af86315988d4596bf0fb71f64bf338d864e30d5b11374acf02e7f58b31a9d76a33557f7b193dbc561b2dc72db9329"
    },
    %{
      privkey: 0x624FB68C6C2474358EF57A9810BA5A17855D0FF8676D5D80E93DF314D5C3D277,
      pubkey: 0x4af83421073f24e51235c43ffb85aa94dc3139af958a2532c6b412832fbbacc4,
      tweak_secret: 0xF1997F60060268C14B81744869AEB04098A93704C3BDA2A640A1B26F74E246F4,
      tweak_point: 0xb9dc16baaf262b3a60a1979833f9ca350e2219121fdb43d3fd2045d3142bb71f,
      message_hash: 0x97FF15503ECA5167E871E04998F3C90976E8FAFF9AD1AF54F045153BA41E1663,
      aux_rand: 0x71C1FE1F3A27B04EEC4142AC1612A7C6419B1740716E2C29CEE319E718950A04,
      untweaked_sig: "08365373469000bca3fa28a95469f6331a20d4f03429372573b3c2d3d3d5b0f6801f053ece6e34cdf9fa8f43ec2ed3b730c388c0e444dd45f9cc1f920adac25f",
      tweaked_sig: "9e3deb23f27730ce1be854b0145cc9bf99e3ee10491d28308160c7b65b0a56e871b8849ed4709d8f457c038c55dd83f90ebde2def8b9dfb07a9b7374af86c812"
    },
    %{
      privkey: 0xB5196100AAC42311C9B33B1746CA0B38AC4547936DDC4AFFF547A862A4BF9890,
      pubkey: 0x5b279f79dcf2414b66160515de53ac471a043d6d9f62fd007c09ad90704ffd28,
      tweak_secret: 0xA69690763B4034FCF0F269E80464643E521475BFE08162632971AE0BDAA7AE8E,
      tweak_point: 0xe9f219bb7c0a390a7df96a4f33b7f7d6179a9a4aa216ed1a750ddba1719072f0,
      message_hash: 0xAD6F06747576C8EC210113A2C070A7A5688616EE841FA61026D2FF1CF9F7970F,
      aux_rand: 0x63241AA5C78B99A849025EB3056E84DB011769DC8BBE782FAFA6E89D2BEE0C16,
      untweaked_sig: "ef3766f37e9235e9652418bd60c54cd8e9c2db06f7effc542415fc76fac9c5cb75cc36cc9d5c20d303c30e43c2be82708141b8f721f75c7f889ebb24da81c818",
      tweaked_sig: "aa9788a104f497f788bf4979a791a04c8408fd2f82075d5810f5f85394d567761c62c742d89c55cff4b5782bc722e6b018a751d053301ea6f23e0aa3e4f33565"
    },
    %{
      privkey: 0x45AC71188B8B3B180D806ABB0289AB23357BF7CE866BFDB13509C68BAC5C88C4,
      pubkey: 0x8b688d7ce32ab13bed3f0c5f119791f8b76913809c22983c8b6713d6fdc6f5a3,
      tweak_secret: 0x6D2B06A08C0F20A64FA06DADF35F992F4DA441A29541268FB5F9AA9B7977A886,
      tweak_point: 0x4d01a75b79ad34ce9d1dec59c581881db6a05865807705558a31e5b19047b024,
      message_hash: 0x1E3D05CC94304EB6CEF384D5ADF36827A6CA4299D70B821B60240995F75BB6CB,
      aux_rand: 0x7EFC5AD98D6AA0542A9534FA8637AB87A1B8E48FBAFD89AC6EA9348B44EEA049,
      untweaked_sig: "655244da978cb1fa37690f3fe98c0e78b58390207781dae0d57f74dde06c0c3f6c8463e2c5f1e4dcabdfa050d9f18e3dfdd4bd70b55a024f3beab45fecb6e255",
      tweaked_sig: "29abdd275d062b0bef51113fabaf3a70652387e7fa227c54b968b4943a7f4312d9af6a8352010582fb800dfecd51276d4b78ff134a9b28def1e45efb662e8adb"
    },
    %{
      privkey: 0x24D807AB16645D504C75AA9B6355444FC291298AABEB4DAC5EB070898AD645B0,
      pubkey: 0xf7609d85839d360fdba6a7bcde848807baeb6417d5ed4258c1c8bc4650543c7a,
      tweak_secret: 0x4ABE441BF15DBB0378C2763FCA1E967EFA2636C6292A80711DA55AC7810CAA2A,
      tweak_point: 0x6690f7703df1a815d8b4391889c47d8d8837369c6f2e00d5eb92abf1b90a206f,
      message_hash: 0x9AE6F80954DA7A3D615987FC0CE97CC4E4567F5425A733DBD4C0BD496A3D5622,
      aux_rand: 0xA421B1D6C0DA447395A19B0CF5BBB9879DAE8303CFD33C46F001DBE7EFE9853,
      untweaked_sig: "96b4d6d0a19e7f42eea9ee4ad8d36a19e039623eeea47a6fb1658df2e20f7e23cbc02c5c59d7961cf88402a346584af229cb795295c5ea108440bd7de5ea01f0",
      tweaked_sig: "a57c39c39b18fd5e6f572253e19227252a4a81a4ac3dc1ef804e6b306b142b10167e70784b355120714678e31076e1726942d3320fa7ca45e213b9b896c06ad9"
    },
    %{
      privkey: 0x7EDA1030020279FA24CC33B79A665B73A9E715EB1EB2C6DBEBEE21AD7BCF1E2C,
      pubkey: 0x65c57e92bd052d623ac708c34a9a73851e37c81cb763b9fe1ff88437ce42245f,
      tweak_secret: 0x1DE275F6F723416882A18E0F4CCD398B7AA9C2A701BFD16D448A118BF82D3027,
      tweak_point: 0xcbc6ed86f4442c6403d5c0a3b8157489c5cc55d5137bbd4648c58301979b6f6c,
      message_hash: 0xA744D50F65508DDE9278AECAD6A2759BE3A83709877B427E4098085DB27B9826,
      aux_rand: 0x12F582D5FA0B2F6245985FBC7C7220C55D441D027B64BA2A7289B9A15E5106F7,
      untweaked_sig: "454d9f3fe892e1f31638a258b135ddb74beaed682936830b1d233432e7a2a575d9953241a92d0172bf8df6e198dc7a9052638337483e0881ccb96ba38ea973d3",
      tweaked_sig: "db076ae6615ccd083a0d8e6d9e78c28cba696f4c4d3fbfb5c5a55b23d4de0d0af777a838a05042db422f84f0e5a9b41bcd0d45de49fdd9ef11437d2f86d6a3fa"
    },
    %{
      privkey: 0x95896701D713F8AA383176C2BCD61F8EC55A29C5169AEBE9A8A32AC9803F8E7D,
      pubkey: 0xe7d2b5e311e4f7e81d05c5c56a94f0e5438da78b2e512f78b540114dcf931080,
      tweak_secret: 0x7038F53CA5C13C1534A595BC74799657805CB864A21AC78618E661E2A27F6DE4,
      tweak_point: 0xe76f186a03ef4ca41b55ff18e2de2f713cf9a1f97f23f627681a2a47bea24a95,
      message_hash: 0x4928F4C94434C570F12CF548F4B2F4C9124F5E6D1371020D55EC3D508DA49D61,
      aux_rand: 0x51DDDD197BF29EE74235C80CECBE06C8E012BFFC0E227E87A966AD9BB6E6A07B,
      untweaked_sig: "46d4e627dc2a8d3864f4e6738f88ab891e5e51da7b08251218d11b0f56f047b4d91271d08e0ba2ecde0169ce02307e49bca6cc749e3c6869dad5ace39f09c943",
      tweaked_sig: "83ba54b75d4516cb376b51fc8fb9cd560aae652a2ff8cded96cb052ed3b1e12e494b670d33ccdf0212a6ff8a76aa14a28254a7f2910e8fb433e9b0397152f5e6"
    },
    %{
      privkey: 0x695563958BE07A20700F6B624C2EBA9F336C47ADF7B8E202388600132D2E7CF3,
      pubkey: 0x97826ac90a2e8ebf9c2f94c5f23863aed915b4c4e77701b9ef7b43e9c501d0f3,
      tweak_secret: 0x6FDDBC57B407184C1D1C0B9040A14A19EF8824222431F39CB89FED2C9D67CE41,
      tweak_point: 0xe772ca746c6f40e607167f6d95414dab603fb36e0a4e473ab69d6e1036c209ea,
      message_hash: 0x9A6BBFEF82261C8EFA9CD7F3481728D68554B2E698187797EAF60A734B6307D9,
      aux_rand: 0x1ED0360C5241E28038735B43C6705AE2A1A971CDD94FCED6817C005ED2DF8237,
      untweaked_sig: "d44e4a61254b90b671a278ee8ae73add71c5cb89b9fda0611cabb3ab46c4bb5d2511324a297a4027f3bef12a79e07a16d1419922e0d6c205066b538efc655dfe",
      tweaked_sig: "840a95a2d67b1fe09584a2b9f353277c318d4b21774a777a2dd2814de4e9d22094eeeea1dd81587410dafcbaba81c430c0c9bd450508b5a1bf0b40bb99cd2c3f"
    }
  ]

  describe "adaptor signature tests" do
    test "test adaptor signatures" do
      for t <- @schnorr_adaptor_signatures do
        {:ok, sk} = PrivateKey.new(t.privkey)
        sk = Secp256k1.force_even_y(sk)
        pk = PrivateKey.to_point(sk)
        # check pubkey is correct
        assert t.pubkey == pk.x

        {:ok, tw} = PrivateKey.new(t.tweak_secret)
        tw = Secp256k1.force_even_y(tw)
        tw_point = PrivateKey.to_point(tw)
        # check tweak point is correct
        assert t.tweak_point == tw_point.x

        # parse sigs
        {:ok, c_ut_sig} = Signature.parse_signature(t.untweaked_sig)
        {:ok, c_tw_sig} = Signature.parse_signature(t.tweaked_sig)

        {:ok, ut_sig, t_point} = Schnorr.sign_for_tweak(sk, t.message_hash, t.aux_rand, tw_point)
        # check tweak point hasn't changed
        assert t_point == tw_point
        # check untweaked sig
        assert c_ut_sig == ut_sig
        # adaptor sig is not a valid schnorr sig, must fail
        assert !Schnorr.verify_signature(pk, t.message_hash, ut_sig)
        # verify adaptor signature
        assert Schnorr.verify_untweaked_signature(pk, t.message_hash, ut_sig, tw_point)
        # complete adaptor sig
        tw_sig = Schnorr.tweak_signature(ut_sig, tw)
        # check sig
        assert c_tw_sig == tw_sig
        # ensure tweaked sig is same when using tweak private key and integer
        tw_sig0 = Schnorr.tweak_signature(ut_sig, tw.d)
        assert tw_sig == tw_sig0

        # complete sig must be valid schnorr sig
        assert Schnorr.verify_signature(pk, t.message_hash, tw_sig)

        # extract tweak secret
        {:ok, tweak} = Schnorr.extract_tweak(pk, t.message_hash, ut_sig, tw_sig)
        assert tweak == tw.d
        assert t.tweak_secret == tweak

        # extract signature given tweak
        {:ok, sig} = Schnorr.extract_tweaked_signature(pk, t.message_hash, ut_sig, t.tweak_secret)
        assert sig == tw_sig
      end
    end
  end
end
