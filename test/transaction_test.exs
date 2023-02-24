defmodule Bitcoinex.TransactionTest do
  use ExUnit.Case
  doctest Bitcoinex.Transaction

  alias Bitcoinex.Transaction
  alias Bitcoinex.Utils
  alias Bitcoinex.Script
  alias Bitcoinex.Taproot
  alias Bitcoinex.Secp256k1.{PrivateKey, Schnorr, Signature}

  @txn_serialization_1 %{
    tx_hex:
      "01000000010470c3139dc0f0882f98d75ae5bf957e68dadd32c5f81261c0b13e85f592ff7b0000000000ffffffff02b286a61e000000001976a9140f39a0043cf7bdbe429c17e8b514599e9ec53dea88ac01000000000000001976a9148a8c9fd79173f90cf76410615d2a52d12d27d21288ac00000000"
  }

  @txn_segwit_serialization_1 %{
    tx_hex:
      "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
  }

  @txn_segwit_serialization_2 %{
    tx_hex:
      "01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000"
  }

  @txn_segwit_serialization_3 %{
    tx_hex:
      "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
  }

  @txn_segwit_serialization_4 %{
    tx_hex:
      "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000"
  }

  # https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.jsonå
  @bip341_test_vector %{
    given: %{
      unsigned_tx:
        "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d",
      inputs: [
        %{
          prev_scriptpubkey:
            "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
          amount_sats: 420_000_000
        },
        %{
          prev_scriptpubkey:
            "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
          amount_sats: 462_000_000
        },
        %{
          prev_scriptpubkey: "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
          amount_sats: 294_000_000
        },
        %{
          prev_scriptpubkey:
            "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
          amount_sats: 504_000_000
        },
        %{
          prev_scriptpubkey:
            "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
          amount_sats: 630_000_000
        },
        %{
          prev_scriptpubkey: "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc",
          amount_sats: 378_000_000
        },
        %{
          prev_scriptpubkey:
            "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
          amount_sats: 672_000_000
        },
        %{
          prev_scriptpubkey:
            "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
          amount_sats: 546_000_000
        },
        %{
          prev_scriptpubkey:
            "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
          amount_sats: 588_000_000
        }
      ]
    },
    intermediary: %{
      hash_amounts: "58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde6",
      hash_outputs: "a2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc5",
      hash_prevouts: "e3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f",
      hash_script_pubkeys: "23ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e21",
      hash_sequences: "18959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e"
    },
    input_spending: [
      %{
        given: %{
          txin_index: 0,
          internal_privkey: "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa",
          merkle_root: nil,
          hash_type: 3
        },
        intermediary: %{
          internal_pubkey: "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
          tweak: "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
          tweaked_privkey: "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9",
          sigmsg:
            "0003020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e0000000000d0418f0e9a36245b9a50ec87f8bf5be5bcae434337b87139c3a5b1f56e33cba0",
          precomputed_used: [
            "hash_amounts",
            "hash_prevouts",
            "hash_script_pubkeys",
            "hash_sequences"
          ],
          sig_hash: "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555"
        },
        expected: %{
          witness: [
            "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03"
          ]
        }
      },
      %{
        given: %{
          txin_index: 1,
          internal_privkey: "1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f",
          merkle_root: "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
          hash_type: 131
        },
        intermediary: %{
          internal_pubkey: "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
          tweak: "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
          tweaked_privkey: "ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080",
          sigmsg:
            "0083020000000065cd1d00d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd9900000000808f891b00000000225120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3ffffffffffcef8fb4ca7efc5433f591ecfc57391811ce1e186a3793024def5c884cba51d",
          precomputed_used: [],
          sig_hash: "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d"
        },
        expected: %{
          witness: [
            "052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f83"
          ]
        }
      },
      %{
        given: %{
          txin_index: 3,
          internal_privkey: "d3c7af07da2d54f7a7735d3d0fc4f0a73164db638b2f2f7c43f711f6d4aa7e64",
          merkle_root: "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
          hash_type: 1
        },
        intermediary: %{
          internal_pubkey: "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
          tweak: "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
          tweaked_privkey: "97323385e57015b75b0339a549c56a948eb961555973f0951f555ae6039ef00d",
          sigmsg:
            "0001020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957ea2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc50003000000",
          precomputed_used: [
            "hash_amounts",
            "hash_outputs",
            "hash_prevouts",
            "hash_script_pubkeys",
            "hash_sequences"
          ],
          sig_hash: "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669"
        },
        expected: %{
          witness: [
            "ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a01"
          ]
        }
      },
      %{
        given: %{
          txin_index: 4,
          internal_privkey: "f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e",
          merkle_root: "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
          hash_type: 0
        },
        intermediary: %{
          internal_pubkey: "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
          tweak: "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
          tweaked_privkey: "a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501",
          sigmsg:
            "0000020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957ea2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc50004000000",
          precomputed_used: [
            "hash_amounts",
            "hash_outputs",
            "hash_prevouts",
            "hash_script_pubkeys",
            "hash_sequences"
          ],
          sig_hash: "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef"
        },
        expected: %{
          witness: [
            "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f"
          ]
        }
      },
      %{
        given: %{
          txin_index: 6,
          internal_privkey: "415cfe9c15d9cea27d8104d5517c06e9de48e2f986b695e4f5ffebf230e725d8",
          merkle_root: "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def",
          hash_type: 2
        },
        intermediary: %{
          internal_pubkey: "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
          tweak: "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
          tweaked_privkey: "241c14f2639d0d7139282aa6abde28dd8a067baa9d633e4e7230287ec2d02901",
          sigmsg:
            "0002020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e0006000000",
          precomputed_used: [
            "hash_amounts",
            "hash_prevouts",
            "hash_script_pubkeys",
            "hash_sequences"
          ],
          sig_hash: "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85"
        },
        expected: %{
          witness: [
            "a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee002"
          ]
        }
      },
      %{
        given: %{
          txin_index: 7,
          internal_privkey: "c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103",
          merkle_root: "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
          hash_type: 130
        },
        intermediary: %{
          internal_pubkey: "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
          tweak: "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
          tweaked_privkey: "65b6000cd2bfa6b7cf736767a8955760e62b6649058cbc970b7c0871d786346b",
          sigmsg:
            "0082020000000065cd1d00e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf00000000804c8b2000000000225120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5ffffffff",
          precomputed_used: [],
          sig_hash: "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10"
        },
        expected: %{
          witness: [
            "ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c482"
          ]
        }
      },
      %{
        given: %{
          txin_index: 8,
          internal_privkey: "77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa",
          merkle_root: "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
          hash_type: 129
        },
        intermediary: %{
          internal_pubkey: "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
          tweak: "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
          tweaked_privkey: "ec18ce6af99f43815db543f47b8af5ff5df3b2cb7315c955aa4a86e8143d2bf5",
          sigmsg:
            "0081020000000065cd1da2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc500a778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af101000000002b0c230000000022512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220ffffffff",
          precomputed_used: [
            "hash_outputs"
          ],
          sig_hash: "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2"
        },
        expected: %{
          witness: [
            "bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd981"
          ]
        }
      }
    ],
    auxiliary: %{
      signed_tx:
        "020000000001097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a41842000000006b4830450221008f3b8f8f0537c420654d2283673a761b7ee2ea3c130753103e08ce79201cf32a022079e7ab904a1980ef1c5890b648c8783f4d10103dd62f740d13daa79e298d50c201210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0141ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c030141052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f83000141ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a010140b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f0247304402202b795e4de72646d76eab3f0ab27dfa30b810e856ff3a46c9a702df53bb0d8cc302203ccc4d822edab5f35caddb10af1be93583526ccfbade4b4ead350781e2f8adcd012102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f90141a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee0020141ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c4820141bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd9810065cd1d"
    }
  }

  # https://gist.github.com/giacomocaironi/e41a45195b2ac6863ec46e8f86324757
  @bip341_sighash_all %{
    sighash_flag: 0x00,
    unsigned_tx:
      "02000000025f6092ec9bb430830dfc344260dd5a03cf355186e774be49b2fe5c362f56cb8d00000000000000000061431892d76aa28b5ed1e3da8800fa0d7190c4b4f22be5f416d2d07e573b32e10100000000000000000100ca9a3b000000001976a914682dfdbc97ab5c31300f36d3c12c6fd854b1b35a88ac00000000",
    signed_tx:
      "020000000001025f6092ec9bb430830dfc344260dd5a03cf355186e774be49b2fe5c362f56cb8d00000000000000000061431892d76aa28b5ed1e3da8800fa0d7190c4b4f22be5f416d2d07e573b32e10100000000000000000100ca9a3b000000001976a914682dfdbc97ab5c31300f36d3c12c6fd854b1b35a88ac0247304402203120452eed289de04e17740232b5f97fac0bc91e4cbb7750bb3d9f4f3c09477b02207e4e363c8d7914f707ff3ddf84e3201f9e402a7dccd02be5d7739d91b0f91adf01210271be339aeae9ed2c6a5a7f8ac5f49638da387612be881c7ed2fb3848b0ef8a6c01408608a76e87a5be42162284e8d7efc6cf71470351b36e07914fd0cfcb7beae98378fd9f664e274c9c2a2744197da522fdf1e3aba999b318e2587be098d90d453300000000",
    inputs: [
      %{
        prev_scriptpubkey: "0014196a5bea745288a7f947993c28e3a0f2108d2e0a",
        value: 500_000_000,
        privkey: "6b3973ee2ce444ada0147716925f6f77569350804835498593dd3be95163d558",
        pubkey: "0271be339aeae9ed2c6a5a7f8ac5f49638da387612be881c7ed2fb3848b0ef8a6c"
      },
      %{
        prev_scriptpubkey: "512029d942d0408906b359397b6f87c5145814a9aefc8c396dd05efa8b5b73576bf2",
        value: 600_000_000,
        privkey: "cf3780a32ef3b2d70366f0124ee40195a251044e82a13146106be75ee049ac02",
        # We don't know what aux was used, so this can't be recreated :/
        signature:
          "8608a76e87a5be42162284e8d7efc6cf71470351b36e07914fd0cfcb7beae98378fd9f664e274c9c2a2744197da522fdf1e3aba999b318e2587be098d90d4533"
      }
    ],
    intermediary: %{
      data:
        "0000020000000000000032553b113292dfa8216546e721388a6c19c76626ca65dc187e0348d6ed445f815733468db74734c00efa0b466bca091d8f1aab074af2538f36bd0a734a5940c5423cd73484fc5e3e0a623442846c279c2216f25a2f32d161fea6c5821a1adde7af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc8cdee56004a241f9c79cc55b7d79eaed04909d84660502a2d4e9c357c2047cf50001000000",
      sighash: "07333acfe6dce8196f1ad62b2e039a3d9f0b6627bf955be767c519c0f8789ff4",
      sha_prevouts: %{
        data:
          "5f6092ec9bb430830dfc344260dd5a03cf355186e774be49b2fe5c362f56cb8d0000000061431892d76aa28b5ed1e3da8800fa0d7190c4b4f22be5f416d2d07e573b32e101000000",
        hash: "32553b113292dfa8216546e721388a6c19c76626ca65dc187e0348d6ed445f81"
      },
      sha_amounts: %{
        data: "0065cd1d000000000046c32300000000",
        hash: "5733468db74734c00efa0b466bca091d8f1aab074af2538f36bd0a734a5940c5"
      },
      sha_scriptpubkeys: %{
        data:
          "160014196a5bea745288a7f947993c28e3a0f2108d2e0a22512029d942d0408906b359397b6f87c5145814a9aefc8c396dd05efa8b5b73576bf2",
        hash: "423cd73484fc5e3e0a623442846c279c2216f25a2f32d161fea6c5821a1adde7"
      },
      sha_sequences: %{
        data: "0000000000000000",
        hash: "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"
      },
      sha_outputs: %{
        data: "00ca9a3b000000001976a914682dfdbc97ab5c31300f36d3c12c6fd854b1b35a88ac",
        hash: "8cdee56004a241f9c79cc55b7d79eaed04909d84660502a2d4e9c357c2047cf5"
      }
    }
  }

  # SIGHASH_ANYONECANPAY(ALL)
  @bip341_sighash_anyonecanpay_all %{
    sighash_flag: 0x81,
    unsigned_tx:
      "02000000015c82840e7a0e5283c5516e742352566408de5c40d45ab0a2f872b37f188976c200000000000000000002003b5808000000001600141192fac5233e4eefa18859396b74851de18f8f4700e1f5050000000022512032c22a6e048b9d4183f612bc1b73a58fc0d4e7f548fd71b732063645d43f420200000000",
    signed_tx:
      "020000000001015c82840e7a0e5283c5516e742352566408de5c40d45ab0a2f872b37f188976c200000000000000000002003b5808000000001600141192fac5233e4eefa18859396b74851de18f8f4700e1f5050000000022512032c22a6e048b9d4183f612bc1b73a58fc0d4e7f548fd71b732063645d43f4202014153fd82ff31642b92ae43cf0010e2aac2c51a781cb2ce8c72f80477a4900d2f3a4bb1eb986bc000bd5b055c62872ac8c426eb69186b3f2e46656189d1ba97a3078100000000",
    inputs: [
      %{
        prev_scriptpubkey: "5120fe7633a26b281a80ee75d344b07ec97e738d4038de288b6caf7d38e06a6c3ee1",
        value: 250_000_000,
        privkey: "3c1d300faf1d8706fd07137e1cc1d59967ccc0efa6212fc03b2ac7c382fa9133",
        # has sighash anyonecanpay appended
        signature:
          "53fd82ff31642b92ae43cf0010e2aac2c51a781cb2ce8c72f80477a4900d2f3a4bb1eb986bc000bd5b055c62872ac8c426eb69186b3f2e46656189d1ba97a30781"
      }
    ],
    intermediary: %{
      data:
        "00810200000000000000d070f96ca70c4dea1042a92e6abf04883e75bd3ad7dd4dcdf18153cda431cbd8005c82840e7a0e5283c5516e742352566408de5c40d45ab0a2f872b37f188976c20000000080b2e60e00000000225120fe7633a26b281a80ee75d344b07ec97e738d4038de288b6caf7d38e06a6c3ee100000000",
      sighash: "11998278e8f4fe9ec6e360642a91536a5498a30cf711712ed3d9c25dfede876b",
      sha_outputs: %{
        data:
          "003b5808000000001600141192fac5233e4eefa18859396b74851de18f8f4700e1f5050000000022512032c22a6e048b9d4183f612bc1b73a58fc0d4e7f548fd71b732063645d43f4202",
        hash: "d070f96ca70c4dea1042a92e6abf04883e75bd3ad7dd4dcdf18153cda431cbd8"
      }
    }
  }

  describe "decode/1" do
    test "decodes legacy bitcoin transaction" do
      txn_test = @txn_serialization_1
      {:ok, txn} = Transaction.decode(txn_test.tx_hex)
      assert 1 == length(txn.inputs)
      assert 2 == length(txn.outputs)
      assert 1 == txn.version
      assert nil == txn.witnesses
      assert 0 == txn.lock_time

      assert "b020bdec4e92cb69db93557dcbbfcc73076fc01f6828e41eb3ef5f628414ee62" ==
               Transaction.transaction_id(txn)

      in_1 = Enum.at(txn.inputs, 0)

      assert "7bff92f5853eb1c06112f8c532ddda687e95bfe55ad7982f88f0c09d13c37004" == in_1.prev_txid
      assert 0 == in_1.prev_vout
      assert "" == in_1.script_sig
      assert 4_294_967_295 == in_1.sequence_no

      out_0 = Enum.at(txn.outputs, 0)
      assert 514_229_938 == out_0.value
      assert "76a9140f39a0043cf7bdbe429c17e8b514599e9ec53dea88ac" == out_0.script_pub_key

      out_1 = Enum.at(txn.outputs, 1)
      assert 1 == out_1.value
      assert "76a9148a8c9fd79173f90cf76410615d2a52d12d27d21288ac" == out_1.script_pub_key
    end

    test "decodes native segwit p2wpkh bitcoin transaction" do
      txn_test = @txn_segwit_serialization_1
      {:ok, txn} = Transaction.decode(txn_test.tx_hex)
      assert 2 == length(txn.inputs)
      assert 2 == length(txn.outputs)
      assert 1 == txn.version
      assert 2 == length(txn.witnesses)
      assert 17 == txn.lock_time

      assert "e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609" ==
               Transaction.transaction_id(txn)

      in_1 = Enum.at(txn.inputs, 0)

      assert "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff" == in_1.prev_txid
      assert 0 == in_1.prev_vout

      assert "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01" ==
               in_1.script_sig

      assert 4_294_967_278 == in_1.sequence_no

      in_2 = Enum.at(txn.inputs, 1)

      assert "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef" == in_2.prev_txid
      assert 1 == in_2.prev_vout
      assert "" == in_2.script_sig
      assert 4_294_967_295 == in_2.sequence_no

      witness_in_0 = Enum.at(txn.witnesses, 0)
      assert 0 == witness_in_0.txinwitness

      witness_in_1 = Enum.at(txn.witnesses, 1)

      assert [
               "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
               "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
             ] == witness_in_1.txinwitness

      out_0 = Enum.at(txn.outputs, 0)
      assert 112_340_000 == out_0.value
      assert "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac" == out_0.script_pub_key

      out_1 = Enum.at(txn.outputs, 1)
      assert 223_450_000 == out_1.value
      assert "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac" == out_1.script_pub_key
    end

    test "decodes native segwit p2wsh bitcoin transaction" do
      txn_test = @txn_segwit_serialization_2
      {:ok, txn} = Transaction.decode(txn_test.tx_hex)
      assert 2 == length(txn.inputs)
      assert 1 == length(txn.outputs)
      assert 1 == txn.version
      assert 2 == length(txn.witnesses)
      assert 0 == txn.lock_time

      assert "570e3730deeea7bd8bc92c836ccdeb4dd4556f2c33f2a1f7b889a4cb4e48d3ab" ==
               Transaction.transaction_id(txn)

      in_0 = Enum.at(txn.inputs, 0)

      assert "6eb316926b1c5d567cd6f5e6a84fec606fc53d7b474526d1fff3948020c93dfe" == in_0.prev_txid
      assert 0 == in_0.prev_vout

      assert "47304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201" ==
               in_0.script_sig

      assert 4_294_967_295 == in_0.sequence_no

      in_1 = Enum.at(txn.inputs, 1)

      assert "f825690aee1b3dc247da796cacb12687a5e802429fd291cfd63e010f02cf1508" == in_1.prev_txid
      assert 0 == in_1.prev_vout
      assert "" == in_1.script_sig
      assert 4_294_967_295 == in_1.sequence_no

      witness_in_0 = Enum.at(txn.witnesses, 0)
      assert 0 == witness_in_0.txinwitness

      witness_in_1 = Enum.at(txn.witnesses, 1)

      assert [
               "304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503",
               "3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e2703",
               "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
             ] == witness_in_1.txinwitness

      out_1 = Enum.at(txn.outputs, 0)
      assert 5_000_000_000 == out_1.value
      assert "76a914a30741f8145e5acadf23f751864167f32e0963f788ac" == out_1.script_pub_key
    end

    test "decodes segwit p2sh-pw2pkh bitcoin transaction" do
      txn_test = @txn_segwit_serialization_3
      {:ok, txn} = Transaction.decode(txn_test.tx_hex)
      assert 1 == length(txn.inputs)
      assert 2 == length(txn.outputs)
      assert 1 == txn.version
      assert 1 == length(txn.witnesses)
      assert 1170 == txn.lock_time

      assert "ef48d9d0f595052e0f8cdcf825f7a5e50b6a388a81f206f3f4846e5ecd7a0c23" ==
               Transaction.transaction_id(txn)

      in_0 = Enum.at(txn.inputs, 0)

      assert "77541aeb3c4dac9260b68f74f44c973081a9d4cb2ebe8038b2d70faa201b6bdb" == in_0.prev_txid
      assert 1 == in_0.prev_vout

      assert "16001479091972186c449eb1ded22b78e40d009bdf0089" ==
               in_0.script_sig

      assert 4_294_967_294 == in_0.sequence_no

      witness_in_0 = Enum.at(txn.witnesses, 0)

      assert [
               "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01",
               "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
             ] == witness_in_0.txinwitness

      out_0 = Enum.at(txn.outputs, 0)
      assert 199_996_600 == out_0.value
      assert "76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac" == out_0.script_pub_key

      out_1 = Enum.at(txn.outputs, 1)
      assert 800_000_000 == out_1.value
      assert "76a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac" == out_1.script_pub_key
    end

    test "decodes segwit p2sh-p2wsh bitcoin transaction" do
      txn_test = @txn_segwit_serialization_4
      {:ok, txn} = Transaction.decode(txn_test.tx_hex)
      assert 1 == length(txn.inputs)
      assert 2 == length(txn.outputs)
      assert 1 == txn.version
      assert 1 == length(txn.witnesses)
      assert 0 == txn.lock_time

      assert "27eae69aff1dd4388c0fa05cbbfe9a3983d1b0b5811ebcd4199b86f299370aac" ==
               Transaction.transaction_id(txn)

      in_0 = Enum.at(txn.inputs, 0)

      assert "6eb98797a21c6c10aa74edf29d618be109f48a8e94c694f3701e08ca69186436" == in_0.prev_txid
      assert 1 == in_0.prev_vout

      assert "220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54" ==
               in_0.script_sig

      assert 4_294_967_295 == in_0.sequence_no

      witness_in_0 = Enum.at(txn.witnesses, 0)

      assert [
               "",
               "304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01",
               "3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502",
               "3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403",
               "3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381",
               "3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a0882",
               "30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783",
               "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
             ] == witness_in_0.txinwitness

      out_0 = Enum.at(txn.outputs, 0)
      assert 900_000_000 == out_0.value
      assert "76a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac" == out_0.script_pub_key

      out_1 = Enum.at(txn.outputs, 1)
      assert 87_000_000 == out_1.value
      assert "76a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac" == out_1.script_pub_key
    end
  end

  describe "bip341_sighash" do
    test "BIP341 test vector" do
      t = @bip341_test_vector
      {:ok, unsigned_tx} = Transaction.decode(t.given.unsigned_tx)

      sha_prevouts = Transaction.bip341_sha_prevouts(unsigned_tx.inputs)
      assert sha_prevouts == Utils.hex_to_bin(t.intermediary.hash_prevouts)

      prev_amounts = Enum.map(t.given.inputs, fn input -> input.amount_sats end)
      sha_amounts = Transaction.bip341_sha_amounts(prev_amounts)
      assert sha_amounts == Utils.hex_to_bin(t.intermediary.hash_amounts)

      prev_scriptpubkeys =
        Enum.map(t.given.inputs, fn input ->
          {:ok, s} = Script.parse_script(input.prev_scriptpubkey)
          Script.serialize_with_compact_size(s)
        end)

      sha_scriptpubkeys = Transaction.bip341_sha_scriptpubkeys(prev_scriptpubkeys)
      assert sha_scriptpubkeys == Utils.hex_to_bin(t.intermediary.hash_script_pubkeys)

      sha_sequences = Transaction.bip341_sha_sequences(unsigned_tx.inputs)
      assert sha_sequences == Utils.hex_to_bin(t.intermediary.hash_sequences)

      sha_outputs = Transaction.bip341_sha_outputs(unsigned_tx.outputs)
      assert sha_outputs == Utils.hex_to_bin(t.intermediary.hash_outputs)

      # test sighash for each input
      for i <- t.input_spending do
        sigmsg =
          Transaction.bip341_sigmsg(
            unsigned_tx,
            i.given.hash_type,
            0,
            i.given.txin_index,
            prev_amounts,
            prev_scriptpubkeys
          )

        assert Base.encode16(sigmsg, case: :lower) == i.intermediary.sigmsg

        sighash = Taproot.tagged_hash_tapsighash(sigmsg)
        assert Base.encode16(sighash, case: :lower) == i.intermediary.sig_hash

        {:ok, sk} =
          i.given.internal_privkey
          |> Base.decode16!(case: :lower)
          |> :binary.decode_unsigned()
          |> PrivateKey.new()

        merkle_root =
          if i.given.merkle_root == nil do
            <<>>
          else
            i.given.merkle_root
            |> Utils.hex_to_bin()
          end

        tweaked_sk = Taproot.tweak_privkey(sk, merkle_root)

        assert tweaked_sk.d |> :binary.encode_unsigned() |> Base.encode16(case: :lower) ==
                 i.intermediary.tweaked_privkey

        # BIP341 declares test vectors to all use aux=0
        {:ok, sig} = Schnorr.sign(tweaked_sk, :binary.decode_unsigned(sighash), 0)

        hash_byte =
          if i.given.hash_type == 0x00 do
            <<>>
          else
            <<i.given.hash_type>>
          end

        assert Base.encode16(Signature.serialize_signature(sig) <> hash_byte, case: :lower) ==
                 Enum.at(i.expected.witness, 0)
      end
    end

    test "SIGHASH_ALL" do
      t = @bip341_sighash_all
      {:ok, unsigned_tx} = Transaction.decode(t.unsigned_tx)
      # intermediary hashes
      sha_prevouts = Transaction.bip341_sha_prevouts(unsigned_tx.inputs)
      assert sha_prevouts == Utils.hex_to_bin(t.intermediary.sha_prevouts.hash)

      prev_amounts = Enum.map(t.inputs, fn input -> input.value end)
      sha_amounts = Transaction.bip341_sha_amounts(prev_amounts)
      assert sha_amounts == Utils.hex_to_bin(t.intermediary.sha_amounts.hash)

      prev_scriptpubkeys =
        Enum.map(t.inputs, fn input ->
          {:ok, s} = Script.parse_script(input.prev_scriptpubkey)
          Script.serialize_with_compact_size(s)
        end)

      sha_scriptpubkeys = Transaction.bip341_sha_scriptpubkeys(prev_scriptpubkeys)
      assert sha_scriptpubkeys == Utils.hex_to_bin(t.intermediary.sha_scriptpubkeys.hash)

      sha_sequences = Transaction.bip341_sha_sequences(unsigned_tx.inputs)
      assert sha_sequences == Utils.hex_to_bin(t.intermediary.sha_sequences.hash)

      sha_outputs = Transaction.bip341_sha_outputs(unsigned_tx.outputs)
      assert sha_outputs == Utils.hex_to_bin(t.intermediary.sha_outputs.hash)

      sigmsg =
        Transaction.bip341_sigmsg(
          unsigned_tx,
          t.sighash_flag,
          0,
          1,
          prev_amounts,
          prev_scriptpubkeys
        )

      assert sigmsg == Utils.hex_to_bin(t.intermediary.data)
      sighash = Taproot.tagged_hash_tapsighash(sigmsg)
      assert sighash == Utils.hex_to_bin(t.intermediary.sighash)
    end

    test "SIGHASH_ANYONECANPAY_ALL" do
      t = @bip341_sighash_anyonecanpay_all
      {:ok, unsigned_tx} = Transaction.decode(t.unsigned_tx)

      sha_outputs = Transaction.bip341_sha_outputs(unsigned_tx.outputs)
      assert sha_outputs == Utils.hex_to_bin(t.intermediary.sha_outputs.hash)

      prev_amounts = Enum.map(t.inputs, fn input -> input.value end)

      prev_scriptpubkeys =
        Enum.map(t.inputs, fn input ->
          {:ok, s} = Script.parse_script(input.prev_scriptpubkey)
          Script.serialize_with_compact_size(s)
        end)

      sigmsg =
        Transaction.bip341_sigmsg(
          unsigned_tx,
          t.sighash_flag,
          0,
          0,
          prev_amounts,
          prev_scriptpubkeys
        )

      assert sigmsg == Utils.hex_to_bin(t.intermediary.data)

      sighash = Taproot.tagged_hash_tapsighash(sigmsg)
      assert sighash == Utils.hex_to_bin(t.intermediary.sighash)

      sighash2 =
        Transaction.bip341_sighash(
          unsigned_tx,
          t.sighash_flag,
          0,
          0,
          prev_amounts,
          prev_scriptpubkeys
        )

      assert sighash2 == Utils.hex_to_bin(t.intermediary.sighash)
    end
  end
end
