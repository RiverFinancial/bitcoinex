defmodule TaprootTest do
  use ExUnit.Case
  doctest Bitcoinex.Script

  alias Bitcoinex.Taproot
  alias Bitcoinex.Secp256k1.Point

  @bip_341_script_pubkey_test_vectors [
    %{
      given: %{
        internal_pubkey: "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
        script_tree: nil
      },
      intermediary: %{
        merkle_root: <<>>,
        tweak: "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
        tweaked_pubkey: "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
      },
      expected: %{
        script_pubkey: "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        bip350_address: "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"
      }
    },
    %{
      given: %{
        internal_pubkey: "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
        script_tree:
          Taproot.TapLeaf.from_string(
            # id: 0,
            # version
            192,
            # script
            "20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac"
          )
      },
      intermediary: %{
        leaf_hashes: [
          "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"
        ],
        merkle_root: "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
        tweak: "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
        tweaked_pubkey: "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"
      },
      expected: %{
        script_pubkey: "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        bip350_address: "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586",
        script_path_control_blocks: [
          "c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27"
        ]
      }
    },
    %{
      given: %{
        internal_pubkey: "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
        script_tree:
          Taproot.TapLeaf.from_string(
            # id: 0,
            # version
            192,
            # script
            "20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac"
          )
      },
      intermediary: %{
        leaf_hashes: [
          "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b"
        ],
        merkle_root: "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
        tweak: "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
        tweaked_pubkey: "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e"
      },
      expected: %{
        script_pubkey: "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        bip350_address: "bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5",
        script_path_control_blocks: [
          "c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820"
        ]
      }
    },
    %{
      given: %{
        internal_pubkey: "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
        script_tree: {
          Taproot.TapLeaf.from_string(
            # id: 0,
            # version
            192,
            # script
            "20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac"
          ),
          Taproot.TapLeaf.from_string(
            # id: 1,
            # version
            250,
            # script
            "06424950333431"
          )
        }
      },
      intermediary: %{
        leaf_hashes: [
          "8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7",
          "f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a"
        ],
        merkle_root: "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
        tweak: "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
        tweaked_pubkey: "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5"
      },
      expected: %{
        script_pubkey: "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        bip350_address: "bc1pwyjywgrd0ffr3tx8laflh6228dj98xkjj8rum0zfpd6h0e930h6saqxrrm",
        script_path_control_blocks: [
          "c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a",
          "faee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865928ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7"
        ]
      }
    },
    %{
      given: %{
        internal_pubkey: "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
        script_tree: {
          Taproot.TapLeaf.from_string(
            # id: 0,
            # version
            192,
            # script
            "2044b178d64c32c4a05cc4f4d1407268f764c940d20ce97abfd44db5c3592b72fdac"
          ),
          Taproot.TapLeaf.from_string(
            # id: 1,
            # version
            192,
            # script
            "07546170726f6f74"
          )
        }
      },
      intermediary: %{
        leaf_hashes: [
          "64512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89",
          "2cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb"
        ],
        merkle_root: "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
        tweak: "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
        tweaked_pubkey: "77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220"
      },
      expected: %{
        script_pubkey: "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        bip350_address: "bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq",
        script_path_control_blocks: [
          "c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd82cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb",
          "c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd864512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89"
        ]
      }
    },
    %{
      given: %{
        internal_pubkey: "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
        script_tree: {
          Taproot.TapLeaf.from_string(
            # id: 0,
            192,
            # script
            "2072ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69ac"
          ),
          {
            Taproot.TapLeaf.from_string(
              # id: 1,
              192,
              # script
              "202352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8ac"
            ),
            Taproot.TapLeaf.from_string(
              # id: 2,
              192,
              # script
              "207337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186aac"
            )
          }
        }
      },
      intermediary: %{
        leaf_hashes: [
          "2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817",
          "ba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c",
          "9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf6"
        ],
        merkle_root: "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
        tweak: "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
        tweaked_pubkey: "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605"
      },
      expected: %{
        script_pubkey: "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        bip350_address: "bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e",
        script_path_control_blocks: [
          "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553",
          "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817",
          "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817"
        ]
      }
    },
    %{
      given: %{
        internal_pubkey: "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
        script_tree: {
          Taproot.TapLeaf.from_string(
            # id: 0,
            # version
            192,
            # script
            "2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac"
          ),
          {
            Taproot.TapLeaf.from_string(
              # id: 1,
              # version
              192,
              # script
              "20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac"
            ),
            Taproot.TapLeaf.from_string(
              # id: 2,
              # version
              192,
              # script
              "20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac"
            )
          }
        }
      },
      intermediary: %{
        leaf_hashes: [
          "f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d",
          "737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711",
          "d7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7"
        ],
        merkle_root: "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def",
        tweak: "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
        tweaked_pubkey: "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831"
      },
      expected: %{
        script_pubkey: "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        bip350_address: "bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe",
        script_path_control_blocks: [
          "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91",
          "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312dd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d",
          "c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d"
        ]
      }
    }
  ]

  describe "taproot script_tree" do
    test "calculate_taptweak/2 & tweak_pubkey" do
      for t <- @bip_341_script_pubkey_test_vectors do
        {:ok, pk} = Point.lift_x(t.given.internal_pubkey)
        {_, hash} = Taproot.merkelize_script_tree(t.given.script_tree)
        tweak = Taproot.calculate_taptweak(pk, hash)
        tweak_hex = tweak |> :binary.encode_unsigned() |> Base.encode16(case: :lower)
        assert tweak_hex == t.intermediary.tweak

        tweaked_pubkey = Taproot.tweak_pubkey(pk, hash)
        tweaked_pubkey_hex = tweaked_pubkey |> Point.x_bytes() |> Base.encode16(case: :lower)
        assert tweaked_pubkey_hex == t.intermediary.tweaked_pubkey
      end
    end

    test "merkelize_script_tree/1" do
      for t <- @bip_341_script_pubkey_test_vectors do
        {_, hash} = Taproot.merkelize_script_tree(t.given.script_tree)
        assert Base.encode16(hash, case: :lower) == t.intermediary.merkle_root
      end
    end

    test "build_control_block/3" do
      for t <- @bip_341_script_pubkey_test_vectors do
        {:ok, pk} = Point.lift_x(t.given.internal_pubkey)

        unless t.given.script_tree == nil do
          for {c_control_block, idx} <- Enum.with_index(t.expected.script_path_control_blocks) do
            control_block = Taproot.build_control_block(pk, t.given.script_tree, idx)
            assert Base.encode16(control_block, case: :lower) == c_control_block
          end
        end
      end
    end
  end
end
