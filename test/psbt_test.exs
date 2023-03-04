defmodule Bitcoinex.PSBTTest do
  use ExUnit.Case
  doctest Bitcoinex.PSBT

  alias Bitcoinex.PSBT
  alias Bitcoinex.PSBT.In
  alias Bitcoinex.PSBT.Out
  alias Bitcoinex.PSBT.Global

  @valid_psbts [
    %{
      psbt:
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_294
            }
          ],
          lock_time: 1_257_139,
          outputs: [
            %Bitcoinex.Transaction.Out{
              script_pub_key: "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac",
              value: 99_999_699
            },
            %Bitcoinex.Transaction.Out{
              script_pub_key: "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
              value: 100_000_000
            }
          ],
          version: 2
        }
      },
      expected_in: [
        %In{
          non_witness_utxo: %Bitcoinex.Transaction{
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389",
                prev_vout: 1,
                script_sig: "160014be18d152a9b012039daf3da7de4f53349eecb985",
                sequence_no: 4_294_967_295
              },
              %Bitcoinex.Transaction.In{
                prev_txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886",
                prev_vout: 1,
                script_sig: "160014fe3e9ef1a745e974d902c4355943abcb34bd5353",
                sequence_no: 4_294_967_295
              }
            ],
            lock_time: 0,
            outputs: [
              %Bitcoinex.Transaction.Out{
                script_pub_key: "76a91485cff1097fd9e008bb34af709c62197b38978a4888ac",
                value: 200_000_000
              },
              %Bitcoinex.Transaction.Out{
                script_pub_key: "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                value: 190_303_501_938
              }
            ],
            version: 1,
            witnesses: [
              %Bitcoinex.Transaction.Witness{
                txinwitness: [
                  "304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01",
                  "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"
                ]
              },
              %Bitcoinex.Transaction.Witness{
                txinwitness: [
                  "3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01",
                  "0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3"
                ]
              }
            ]
          }
        }
      ],
      expected_out: [
        %Out{},
        %Out{}
      ]
    },
    %{
      psbt:
        "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_294
            },
            %Bitcoinex.Transaction.In{
              prev_txid: "e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab",
              prev_vout: 1,
              script_sig: "",
              sequence_no: 4_294_967_294
            }
          ],
          lock_time: 0,
          outputs: [
            %Bitcoinex.Transaction.Out{
              script_pub_key: "76a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac",
              value: 199_900_000
            },
            %Bitcoinex.Transaction.Out{
              script_pub_key: "76a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac",
              value: 9358
            }
          ],
          version: 2
        }
      },
      expected_in: [
        %In{
          final_scriptsig: %Bitcoinex.Script{
            items: [
              71,
              <<48, 68, 2, 32, 71, 89, 102, 23, 151, 192, 27, 3, 107, 37, 146, 137, 72, 104, 98,
                24, 52, 125, 137, 134, 75, 113, 158, 31, 127, 207, 87, 209, 229, 17, 101, 135, 2,
                32, 83, 9, 234, 191, 86, 170, 77, 136, 145, 255, 209, 17, 253, 241, 51, 111, 58,
                41, 218, 134, 109, 127, 132, 134, 215, 85, 70, 206, 237, 175, 147, 25, 1>>,
              33,
              <<3, 92, 220, 97, 252, 123, 169, 113, 192, 181, 1, 166, 70, 162, 168, 59, 16, 44,
                180, 56, 129, 33, 124, 166, 130, 220, 134, 226, 215, 63, 168, 130, 146>>
            ]
          }
        },
        %In{
          redeem_script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<133, 209, 53, 55, 242, 226, 101, 64, 90, 52, 219, 175, 169, 227, 221, 160, 31,
                184, 35, 8>>
            ]
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key: "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
            value: 100_000_000
          }
        }
      ],
      expected_out: [
        %Out{},
        %Out{}
      ]
    },
    %{
      psbt:
        "cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "7612ec6d382ddf730922f610da7a5dd5bf658633dcd31bfe99586cc22866fc9d",
              prev_vout: 1,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          lock_time: 0,
          outputs: [
            %Bitcoinex.Transaction.Out{
              script_pub_key: "00147b3a00bfdc14d27795c2b74901d09da6ef133579",
              value: 499_990_000
            }
          ],
          version: 2
        },
        xpub: [
          %{
            derivation: %Bitcoinex.ExtendedKey.DerivationPath{
              child_nums: [2_147_483_822, 2_147_483_648]
            },
            pfp: <<217, 12, 106, 79>>,
            xpub:
              Bitcoinex.ExtendedKey.parse!(
                "tpubDBkJeJo2X94Yq3RVz65DoUgyLUkaDrkfyrn2VcgyCRSKCRonvKvCF2FpYDGJWDkdRHBajXJGpc63GnumUt63ySvqCu2XaTRGVTKMYGuFk9H"
              )
          },
          %{
            derivation: %Bitcoinex.ExtendedKey.DerivationPath{
              child_nums: [2_147_483_822, 2_147_483_649]
            },
            pfp: <<217, 12, 106, 79>>,
            xpub:
              Bitcoinex.ExtendedKey.parse!(
                "tpubDBkJeJo2X94YsvtBEU1eKoibEWiNv51nW5iHhs6VZp59jsE6nen8KZMFyGHuGbCvqjRqirgeMcfpVBkttpUUT6brm4duzSGoZeTbhqCNUu6"
              )
          }
        ]
      },
      expected_in: [
        %In{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_822, 2_147_483_648, 0]
              },
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  71_297_889_195_667_677_566_853_709_053_103_131_423_162_117_776_603_813_866_869_556_867_184_864_299_121,
                y:
                  104_942_558_329_072_212_830_372_841_913_067_137_391_352_852_664_610_839_861_441_469_392_637_640_386_592
              },
              pfp: <<217, 12, 106, 79>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_822, 2_147_483_649, 0]
              },
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  24_953_540_938_576_426_582_583_323_081_660_174_044_181_452_719_495_711_599_804_679_737_956_351_918_091,
                y:
                  115_045_788_123_487_702_367_674_850_763_085_807_099_618_969_835_940_161_186_892_982_331_420_489_690_021
              },
              pfp: <<217, 12, 106, 79>>
            }
          ],
          witness_script:
            "5221029da12cdb5b235692b91536afefe5c91c3ab9473d8e43b533836ab456299c88712103372b34234ed7cf9c1fea5d05d441557927be9542b162eb02e1ab2ce80224c00b52ae",
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key:
              "00202c5486126c4978079a814e13715d65f36459e4d6ccaded266d0508645bafa632",
            value: 500_000_000
          }
        }
      ],
      expected_out: [
        %Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_648, 2_147_483_649]
              },
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  71_916_192_309_307_030_987_819_255_271_417_383_252_226_513_354_309_312_442_460_376_541_014_510_935_801,
                y:
                  87_829_264_540_646_754_532_057_909_755_234_567_745_025_032_566_591_945_062_448_323_127_703_490_972_993
              },
              pfp: <<237, 228, 92, 197>>
            }
          ]
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "39bc5c3b33d66ce3d7852a7942331e3ec10f8ba50f225fc41fb5dfa523239a27",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          lock_time: 0,
          outputs: [
            %Bitcoinex.Transaction.Out{
              script_pub_key: "76a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac",
              value: 199_908_000
            }
          ],
          version: 2
        }
      },
      expected_in: [
        %In{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_648, 2_147_483_652]
              },
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  80_151_448_986_003_541_602_445_390_187_849_273_116_474_332_975_424_144_708_997_035_409_020_762_307_910,
                y:
                  69_508_417_946_258_487_178_124_295_602_214_619_390_077_167_556_721_617_739_677_223_796_084_805_268_603
              },
              pfp: <<180, 166, 186, 103>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_648, 2_147_483_653]
              },
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  100_565_082_940_006_144_500_918_712_336_860_239_214_176_819_872_577_604_419_994_557_980_044_395_840_445,
                y:
                  10_103_911_892_721_234_278_209_537_983_272_986_690_525_296_344_245_993_216_791_872_735_802_656_255_649
              },
              pfp: <<180, 166, 186, 103>>
            }
          ],
          partial_sig: [
            %{
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  80_151_448_986_003_541_602_445_390_187_849_273_116_474_332_975_424_144_708_997_035_409_020_762_307_910,
                y:
                  69_508_417_946_258_487_178_124_295_602_214_619_390_077_167_556_721_617_739_677_223_796_084_805_268_603
              },
              signature:
                "304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01"
            }
          ],
          redeem_script: %Bitcoinex.Script{
            items: [
              0,
              32,
              <<119, 31, 209, 138, 212, 89, 102, 109, 212, 159, 61, 86, 78, 61, 188, 66, 244, 200,
                71, 116, 227, 96, 173, 161, 104, 22, 168, 237, 72, 141, 86, 129>>
            ]
          },
          witness_script:
            "522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae",
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key: "a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87",
            value: 199_909_013
          }
        }
      ],
      expected_out: [
        %Out{}
      ]
    },
    %{
      # finalized psbt
      psbt:
        "cHNidP8BAKcBAAAAAjHC7gs4NF4rUOrlta+j+wB8UHTEuLn0XY6FDUcGybQMAAAAAAD+////NUUKTkDqBbL9oqrAIk9199/ZANXi/8XEgguqQY8iiewAAAAAAP7///8CdImYAAAAAAAiACCs+u6eefBEoqCFYVWhxscCwh/WJZ+286/E8zNH9gRhd4CWmAAAAAAAF6kUV3ZMSDpAgQZkllBPVNL5uRPlwOOHAAAAAAABASuAlpgAAAAAACIAIDH8Jza8S0T6nWkCcU5GqgwxJ2rGEgWFgDSGiJVFJ5W0AQj9/QAEAEgwRQIhALL4SZucnmwtsJ2BguTQkajOkbvRTRcIMF2B/c26pnZDAiAwNPAWsW3b3PxNXZouG43Z2HJ4WufvpjM0x+VlprgFUAFHMEQCIGV66oyrbw0b9HXA8EeGKrIi88YhTGuhpQKdDxX1VivPAiAcxSrameybDohX8yINx2t452PyyqP6qUiTUMNnoAv+twFpUiECZ3pcsDl1tPNTASW/gFEm/PlWLEnQJN5h32F5qmC2U6AhA1fyyfYB3ma7Vg6JKICdCsQFD7/IchNleJnjTaTGbCFgIQP8V/0ULlUTx5q8mJ6eJh6GaCHkHXDkTnmFbpZRGDsQVVOuAAEBK4CWmAAAAAAAIgAgi3WHXCAbeRTULI6EPlb3Z3+J153IX4zK5bHRsqnrSO4BCPwEAEcwRAIgelTwDK+TOYwP6luGb5htloRgijKLoLmNrjk9imXolaICIFQ9Rq0MrOGcrYHC6BZIyyz+tB0Lm8FhqnARl7R+TpyaAUcwRAIgfHNbxYLcTt1yWeADHyo5ye4jtApn+YTgFzK16IsOW0QCIDcOnv2QYaZlc0etz9kfIrkpoepeTndtvEREKROzqqlCAWlSIQIIPVGeoWYEHRGxyDhpzTqE0uBZIjBj5DDXgBX5QWwecCECL5C1pXxiQ5uiuhZASuHYEUq+gXmXqE+wxPnV590o+HAhA0odK6A98KAdcHcI5pcbNfwR1oq0PsofJzNfvSKkdqCMU64AAQFpUiECPhqS90SDpMEqGW1sAlOsWJz63Vlk/z5sY6711XcFHtQhAk0OObM6tXeCqY/Qan0GUzheUJ7jt03EVVnm22OR0xN4IQNsC65rywLkfIV8SA7R0jiIyK1qZrg6sRHLa5JCr7HHJVOuIgICPhqS90SDpMEqGW1sAlOsWJz63Vlk/z5sY6711XcFHtQgAAAAAAAAAIACAACAAgAAAAAAAAAAAAAAAQAAAA0AAAAiAgJNDjmzOrV3gqmP0Gp9BlM4XlCe47dNxFVZ5ttjkdMTeCAAAAAAAAAAgAIAAIACAAAAAAAAAAAAAAABAAAADQAAACICA2wLrmvLAuR8hXxIDtHSOIjIrWpmuDqxEctrkkKvscclIAAAAAAAAACAAgAAgAIAAAAAAAAAAAAAAAEAAAANAAAAAAA=",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "0cb4c906470d858e5df4b9b8c474507c00fba3afb5e5ea502b5e34380beec231",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_294
            },
            %Bitcoinex.Transaction.In{
              prev_txid: "ec89228f41aa0b82c4c5ffe2d500d9dff7754f22c0aaa2fdb205ea404e0a4535",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_294
            }
          ],
          lock_time: 0,
          outputs: [
            %Bitcoinex.Transaction.Out{
              script_pub_key:
                "0020acfaee9e79f044a2a0856155a1c6c702c21fd6259fb6f3afc4f33347f6046177",
              value: 9_996_660
            },
            %Bitcoinex.Transaction.Out{
              script_pub_key: "a91457764c483a4081066496504f54d2f9b913e5c0e387",
              value: 10_000_000
            }
          ],
          version: 1
        }
      },
      expected_in: [
        %In{
          final_scriptwitness: %Bitcoinex.Transaction.Witness{
            txinwitness: [
              "",
              "3045022100b2f8499b9c9e6c2db09d8182e4d091a8ce91bbd14d1708305d81fdcdbaa6764302203034f016b16ddbdcfc4d5d9a2e1b8dd9d872785ae7efa63334c7e565a6b8055001",
              "30440220657aea8cab6f0d1bf475c0f047862ab222f3c6214c6ba1a5029d0f15f5562bcf02201cc52ada99ec9b0e8857f3220dc76b78e763f2caa3faa9489350c367a00bfeb701",
              "522102677a5cb03975b4f3530125bf805126fcf9562c49d024de61df6179aa60b653a0210357f2c9f601de66bb560e8928809d0ac4050fbfc87213657899e34da4c66c21602103fc57fd142e5513c79abc989e9e261e866821e41d70e44e79856e9651183b105553ae"
            ]
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key:
              "002031fc2736bc4b44fa9d6902714e46aa0c31276ac61205858034868895452795b4",
            value: 10_000_000
          }
        },
        %In{
          final_scriptwitness: %Bitcoinex.Transaction.Witness{
            txinwitness: [
              "",
              "304402207a54f00caf93398c0fea5b866f986d9684608a328ba0b98dae393d8a65e895a20220543d46ad0cace19cad81c2e81648cb2cfeb41d0b9bc161aa701197b47e4e9c9a01",
              "304402207c735bc582dc4edd7259e0031f2a39c9ee23b40a67f984e01732b5e88b0e5b440220370e9efd9061a6657347adcfd91f22b929a1ea5e4e776dbc44442913b3aaa94201",
              "522102083d519ea166041d11b1c83869cd3a84d2e059223063e430d78015f9416c1e7021022f90b5a57c62439ba2ba16404ae1d8114abe817997a84fb0c4f9d5e7dd28f87021034a1d2ba03df0a01d707708e6971b35fc11d68ab43eca1f27335fbd22a476a08c53ae"
            ]
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key:
              "00208b75875c201b7914d42c8e843e56f7677f89d79dc85f8ccae5b1d1b2a9eb48ee",
            value: 10_000_000
          }
        }
      ],
      expected_out: [
        %Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_650, 2, 0, 0, 1, 13]
              },
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  28_090_348_957_135_603_138_302_582_488_634_744_063_769_373_744_003_534_936_250_327_398_955_197_210_324,
                y:
                  72_997_351_855_862_386_313_265_421_144_400_773_180_384_569_016_361_889_288_840_365_141_506_887_425_034
              },
              pfp: <<0, 0, 0, 0>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_650, 2, 0, 0, 1, 13]
              },
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  34_853_223_431_373_393_811_263_769_947_202_683_171_474_774_417_547_322_886_690_942_546_874_362_696_568,
                y:
                  113_268_030_251_073_357_691_209_583_004_229_905_838_714_795_934_778_666_512_471_345_919_935_656_053_596
              },
              pfp: <<0, 0, 0, 0>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_650, 2, 0, 0, 1, 13]
              },
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  48_870_426_774_663_552_239_665_427_301_830_100_617_674_007_218_870_368_410_715_268_929_150_665_213_733,
                y:
                  384_321_948_423_668_768_499_139_968_164_679_158_512_264_350_568_463_086_818_860_781_694_386_290_525
              },
              pfp: <<0, 0, 0, 0>>
            }
          ],
          witness_script:
            "5221023e1a92f74483a4c12a196d6c0253ac589cfadd5964ff3e6c63aef5d577051ed421024d0e39b33ab57782a98fd06a7d0653385e509ee3b74dc45559e6db6391d3137821036c0bae6bcb02e47c857c480ed1d23888c8ad6a66b83ab111cb6b9242afb1c72553ae"
        },
        %Out{}
      ]
    },
    %{
      psbt: "cHNidP8BAAoAAAAAAAAAAAAAAA==",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          inputs: [],
          lock_time: 0,
          outputs: [],
          version: 0
        }
      },
      expected_in: [],
      expected_out: []
    },
    %{
      psbt:
        "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEA3wIAAAABJoFxNx7f8oXpN63upLN7eAAMBWbLs61kZBcTykIXG/YAAAAAakcwRAIgcLIkUSPmv0dNYMW1DAQ9TGkaXSQ18Jo0p2YqncJReQoCIAEynKnazygL3zB0DsA5BCJCLIHLRYOUV663b8Eu3ZWzASECZX0RjTNXuOD0ws1G23s59tnDjZpwq8ubLeXcjb/kzjH+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA=",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_294
            },
            %Bitcoinex.Transaction.In{
              prev_txid: "e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab",
              prev_vout: 1,
              script_sig: "",
              sequence_no: 4_294_967_294
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 199_900_000,
              script_pub_key: "76a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac"
            },
            %Bitcoinex.Transaction.Out{
              value: 9358,
              script_pub_key: "76a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac"
            }
          ],
          lock_time: 0
        }
      },
      expected_in: [
        %In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126",
                prev_vout: 0,
                script_sig:
                  "473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31",
                sequence_no: 4_294_967_294
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 99_999_699,
                script_pub_key: "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
              },
              %Bitcoinex.Transaction.Out{
                value: 100_000_000,
                script_pub_key: "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
              }
            ],
            lock_time: 1_257_139
          }
        },
        %In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 100_000_000,
            script_pub_key: "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
          },
          redeem_script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<133, 209, 53, 55, 242, 226, 101, 64, 90, 52, 219, 175, 169, 227, 221, 160, 31,
                184, 35, 8>>
            ]
          }
        }
      ],
      expected_out: [
        %Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_648, 2_147_483_650]
              },
              pfp: <<180, 166, 186, 103>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  106_218_583_072_196_447_736_380_334_552_715_158_727_992_653_635_463_477_362_034_291_905_132_141_629_081,
                y:
                  111_853_877_987_030_790_093_148_386_887_435_750_835_805_008_949_758_207_878_306_607_752_401_323_629_588
              }
            }
          ]
        },
        %Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_649, 2_147_483_650]
              },
              pfp: <<180, 166, 186, 103>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  67_377_249_048_514_558_622_301_148_581_987_854_752_621_201_928_971_282_930_920_275_574_615_944_805_637,
                y:
                  33_878_338_431_620_821_020_481_726_477_149_418_114_572_000_720_118_999_798_151_283_966_732_510_331_525
              }
            }
          ]
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQMEAQAAAAAAAA==",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_294
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 99_999_699,
              script_pub_key: "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
            },
            %Bitcoinex.Transaction.Out{
              value: 100_000_000,
              script_pub_key: "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
            }
          ],
          lock_time: 1_257_139
        }
      },
      expected_in: [
        %In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 1,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389",
                prev_vout: 1,
                script_sig: "160014be18d152a9b012039daf3da7de4f53349eecb985",
                sequence_no: 4_294_967_295
              },
              %Bitcoinex.Transaction.In{
                prev_txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886",
                prev_vout: 1,
                script_sig: "160014fe3e9ef1a745e974d902c4355943abcb34bd5353",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 200_000_000,
                script_pub_key: "76a91485cff1097fd9e008bb34af709c62197b38978a4888ac"
              },
              %Bitcoinex.Transaction.Out{
                value: 190_303_501_938,
                script_pub_key: "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587"
              }
            ],
            witnesses: [
              %Bitcoinex.Transaction.Witness{
                txinwitness: [
                  "304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01",
                  "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"
                ]
              },
              %Bitcoinex.Transaction.Witness{
                txinwitness: [
                  "3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01",
                  "0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3"
                ]
              }
            ],
            lock_time: 0
          },
          sighash_type: 1
        }
      ],
      expected_out: [
        %Out{},
        %Out{}
      ]
    },
    %{
      psbt:
        "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAA=",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          outputs: [%Bitcoinex.Transaction.Out{value: 0, script_pub_key: "6a0100"}],
          lock_time: 0
        }
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          unknown: [
            %{
              key: <<240, 1, 2, 3, 4, 5, 6, 7, 8, 9>>,
              value: <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>
            }
          ]
        }
      ],
      expected_out: [
        %Out{}
      ]
    },
    %{
      psbt:
        "cHNidP8BAJ0BAAAAAnEOp2q0XFy2Q45gflnMA3YmmBgFrp4N/ZCJASq7C+U1AQAAAAD/////GQmU1qizyMgsy8+y+6QQaqBmObhyqNRHRlwNQliNbWcAAAAAAP////8CAOH1BQAAAAAZdqkUtrwsDuVlWoQ9ea/t0MzD991kNAmIrGBa9AUAAAAAFgAUEYjvjkzgRJ6qyPsUHL9aEXbmoIgAAAAATwEEiLIeA55TDKyAAAAAPbyKXJdp8DGxfnf+oVGGAyIaGP0Y8rmlTGyMGsdcvDUC8jBYSxVdHH8c1FEgplPEjWULQxtnxbLBPyfXFCA3wWkQJ1acUDEAAIAAAACAAAAAgAABAR8A4fUFAAAAABYAFDO5gvkbKPFgySC0q5XljOUN2jpKIgIDMJaA8zx9446mpHzU7NZvH1pJdHxv+4gI7QkDkkPjrVxHMEQCIC1wTO2DDFapCTRL10K2hS3M0QPpY7rpLTjnUlTSu0JFAiAthsQ3GV30bAztoITyopHD2i1kBw92v5uQsZXn7yj3cgEiBgMwloDzPH3jjqakfNTs1m8fWkl0fG/7iAjtCQOSQ+OtXBgnVpxQMQAAgAAAAIAAAACAAAAAAAEAAAAAAQEfAOH1BQAAAAAWABQ4j7lEMH63fvRRl9CwskXgefAR3iICAsd3Fh9z0LfHK57nveZQKT0T8JW8dlatH1Jdpf0uELEQRzBEAiBMsftfhpyULg4mEAV2ElQ5F5rojcqKncO6CPeVOYj6pgIgUh9JynkcJ9cOJzybFGFphZCTYeJb4nTqIA1+CIJ+UU0BIgYCx3cWH3PQt8crnue95lApPRPwlbx2Vq0fUl2l/S4QsRAYJ1acUDEAAIAAAACAAAAAgAAAAAAAAAAAAAAiAgLSDKUC7iiWhtIYFb1DqAY3sGmOH7zb5MrtRF9sGgqQ7xgnVpxQMQAAgAAAAIAAAACAAAAAAAQAAAAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 1,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "35e50bbb2a018990fd0d9eae051898267603cc597e608e43b65c5cb46aa70e71",
              prev_vout: 1,
              script_sig: "",
              sequence_no: 4_294_967_295
            },
            %Bitcoinex.Transaction.In{
              prev_txid: "676d8d58420d5c4647d4a872b83966a06a10a4fbb2cfcb2cc8c8b3a8d6940919",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 100_000_000,
              script_pub_key: "76a914b6bc2c0ee5655a843d79afedd0ccc3f7dd64340988ac"
            },
            %Bitcoinex.Transaction.Out{
              value: 99_900_000,
              script_pub_key: "00141188ef8e4ce0449eaac8fb141cbf5a1176e6a088"
            }
          ],
          lock_time: 0
        },
        xpub: [
          %{
            derivation: %Bitcoinex.ExtendedKey.DerivationPath{
              child_nums: [2_147_483_697, 2_147_483_648, 2_147_483_648]
            },
            pfp: <<39, 86, 156, 80>>,
            xpub: %Bitcoinex.ExtendedKey{
              prefix: <<4, 136, 178, 30>>,
              depth: <<3>>,
              parent_fingerprint: <<158, 83, 12, 172>>,
              child_num: <<128, 0, 0, 0>>,
              chaincode:
                <<61, 188, 138, 92, 151, 105, 240, 49, 177, 126, 119, 254, 161, 81, 134, 3, 34,
                  26, 24, 253, 24, 242, 185, 165, 76, 108, 140, 26, 199, 92, 188, 53>>,
              key:
                <<2, 242, 48, 88, 75, 21, 93, 28, 127, 28, 212, 81, 32, 166, 83, 196, 141, 101,
                  11, 67, 27, 103, 197, 178, 193, 63, 39, 215, 20, 32, 55, 193, 105>>,
              checksum: <<230, 83, 80, 24>>
            }
          }
        ]
      },
      expected_in: [
        %In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 100_000_000,
            script_pub_key: "001433b982f91b28f160c920b4ab95e58ce50dda3a4a"
          },
          partial_sig: [
            %{
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  21_976_933_772_883_498_789_027_591_114_401_201_619_393_627_105_936_886_383_472_697_361_469_744_065_884,
                y:
                  7_200_326_197_606_395_130_472_957_753_047_368_877_161_908_639_095_988_897_070_963_103_467_471_435_399
              },
              signature:
                "304402202d704ced830c56a909344bd742b6852dccd103e963bae92d38e75254d2bb424502202d86c437195df46c0ceda084f2a291c3da2d64070f76bf9b90b195e7ef28f77201"
            }
          ],
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_697, 2_147_483_648, 2_147_483_648, 0, 1]
              },
              pfp: <<39, 86, 156, 80>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  21_976_933_772_883_498_789_027_591_114_401_201_619_393_627_105_936_886_383_472_697_361_469_744_065_884,
                y:
                  7_200_326_197_606_395_130_472_957_753_047_368_877_161_908_639_095_988_897_070_963_103_467_471_435_399
              }
            }
          ]
        },
        %In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 100_000_000,
            script_pub_key: "0014388fb944307eb77ef45197d0b0b245e079f011de"
          },
          partial_sig: [
            %{
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  90_220_664_355_153_390_194_324_778_431_845_886_101_502_662_137_446_551_229_950_573_847_917_083_275_536,
                y:
                  30_671_849_324_763_586_853_276_572_668_087_977_292_899_353_337_776_873_336_350_612_915_119_803_985_620
              },
              signature:
                "304402204cb1fb5f869c942e0e26100576125439179ae88dca8a9dc3ba08f7953988faa60220521f49ca791c27d70e273c9b14616985909361e25be274ea200d7e08827e514d01"
            }
          ],
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_697, 2_147_483_648, 2_147_483_648, 0, 0]
              },
              pfp: <<39, 86, 156, 80>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  90_220_664_355_153_390_194_324_778_431_845_886_101_502_662_137_446_551_229_950_573_847_917_083_275_536,
                y:
                  30_671_849_324_763_586_853_276_572_668_087_977_292_899_353_337_776_873_336_350_612_915_119_803_985_620
              }
            }
          ]
        }
      ],
      expected_out: [
        %Out{},
        %Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_697, 2_147_483_648, 2_147_483_648, 0, 4]
              },
              pfp: <<39, 86, 156, 80>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  95_008_039_234_411_418_297_358_865_313_145_660_837_471_761_864_556_347_248_745_408_858_102_616_985_839,
                y:
                  58_958_258_549_746_503_926_788_822_872_770_747_559_389_384_344_394_656_102_791_551_503_991_185_090_332
              }
            }
          ]
        }
      ]
    },
    %{
      psbt: "cHNidP8BAAoAAAAAAAAAAAAAAA==",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 0,
          inputs: [],
          outputs: [],
          lock_time: 0
        }
      },
      expected_in: [],
      expected_out: []
    },
    %{
      psbt:
        "cHNidP8BAEwCAAAAAALT3/UFAAAAABl2qRTQxZkDxbrChodg6Q/VIaRmWqdlIIisAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4ezLhMAAAAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 99_999_699,
              script_pub_key: "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
            },
            %Bitcoinex.Transaction.Out{
              value: 100_000_000,
              script_pub_key: "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
            }
          ],
          lock_time: 1_257_139
        }
      },
      expected_in: [],
      expected_out: [
        %Out{},
        %Out{}
      ]
    },
    # BIP 370 https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#test-vectors
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        version: 2
      },
      expected_in: [
        %In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0,
          sequence: 4_294_967_294
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8BEQSMjcRiARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        fallback_locktime: 0,
        input_count: 1,
        output_count: 2,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0,
          sequence: 4_294_967_294,
          required_time_locktime: 1_657_048_460,
          required_height_locktime: 10000
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEBAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 1,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 2,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEEAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 4,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEIAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Bitcoinex.PSBT.Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 8,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEDAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 3,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEFAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 5,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEGAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 6,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEHAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 7,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgH/AfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      expected_global: %Global{
        tx_version: 2,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 255,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAQYBBwH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BDiALCtkhQZwchxlzXXLcc5+eqeBjjR/kwe7w+ZRAhIFfyAEPBAAAAAABEAT+////AREEjI3EYgESBBAnAAAAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAABBBYAFMQw9kxHVtoxDb0aCFVy7ymZJicsACICAuNvv/U91TQHDPj9OWYUaA81epuF23NAvxz6dF0q17NAGPadhz5UAACAAQAAgAAAAIABAAAAZAAAAAEDCIu96wsAAAAAAQQWABRN0ZOslkpWrBueHMqEVP4vR0+FEwA=",
      expected_global: %Global{
        tx_version: 2,
        fallback_locktime: 0,
        input_count: 1,
        output_count: 2,
        tx_modifiable: 7,
        version: 2
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          non_witness_utxo: %Bitcoinex.Transaction{
            version: 2,
            inputs: [
              %Bitcoinex.Transaction.In{
                prev_txid: "125b805e5a51d715356e3019058dfff3b5f3bf42de932f82a1964b216e25aac1",
                prev_vout: 0,
                script_sig: "",
                sequence_no: 4_294_967_295
              }
            ],
            outputs: [
              %Bitcoinex.Transaction.Out{
                value: 999_999_000,
                script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
              }
            ],
            lock_time: 0
          },
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 999_999_000,
            script_pub_key: "0014b0a3af144208412693ca7d166852b52db0aef06e"
          },
          previous_txid:
            <<11, 10, 217, 33, 65, 156, 28, 135, 25, 115, 93, 114, 220, 115, 159, 158, 169, 224,
              99, 141, 31, 228, 193, 238, 240, 249, 148, 64, 132, 129, 95, 200>>,
          output_index: 0,
          sequence: 4_294_967_294,
          required_time_locktime: 1_657_048_460,
          required_height_locktime: 10000
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 42]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  96_798_430_025_534_287_057_818_182_799_781_202_983_716_126_197_033_126_318_275_350_637_861_242_845_074,
                y:
                  24_577_140_550_790_602_129_463_064_506_346_425_976_399_276_187_317_960_372_865_959_737_887_833_605_246
              }
            }
          ],
          amount: 800_000_000,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<196, 48, 246, 76, 71, 86, 218, 49, 13, 189, 26, 8, 85, 114, 239, 41, 153, 38, 39,
                44>>
            ]
          }
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 1, 100]
              },
              pfp: <<246, 157, 135, 62>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  102_872_461_497_842_797_785_413_923_910_218_265_357_521_021_030_644_560_335_939_528_912_485_972_685_632,
                y:
                  49_593_273_316_372_432_714_030_705_100_641_392_787_703_279_192_668_893_534_395_536_493_521_009_155_774
              }
            }
          ],
          amount: 199_998_859,
          script: %Bitcoinex.Script{
            items: [
              0,
              20,
              <<77, 209, 147, 172, 150, 74, 86, 172, 27, 158, 28, 202, 132, 84, 254, 47, 71, 79,
                133, 19>>
            ]
          }
        }
      ]
    },
    # BIP 371 https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki#test-vectors
    %{
      psbt:
        "cHNidP8BAFICAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAFgAUdo4e60z0IIZgM/gKzv8PlyB0SWkAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgAiAgNrdyptt02HU8mKgnlY3mx4qzMSEJ830+AwRIQkLs5z2Bh3Ky2nVAAAgAEAAIAAAACAAAAAAAAAAAAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "42b224669be683585854193052ef88b1efe2ee963af26c0dfe2730bfba4a7427",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 4_999_997_000,
              script_pub_key: "0014768e1eeb4cf420866033f80aceff0f9720744969"
            }
          ],
          lock_time: 0
        }
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 5_000_000_000,
            script_pub_key: "51205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757"
          },
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 1, 0]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  114_980_336_156_212_694_879_327_992_636_798_621_605_698_402_417_475_818_833_771_862_351_800_336_097_842,
                y:
                  80_701_412_123_039_057_594_876_775_965_687_848_606_566_558_952_919_681_215_239_681_970_556_263_873_620
              }
            }
          ],
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              114_980_336_156_212_694_879_327_992_636_798_621_605_698_402_417_475_818_833_771_862_351_800_336_097_842,
            y:
              80_701_412_123_039_057_594_876_775_965_687_848_606_566_558_952_919_681_215_239_681_970_556_263_873_620
          }
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 0]
              },
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  48_608_022_430_402_926_014_916_497_053_789_681_947_094_617_356_347_258_841_609_839_742_612_155_560_920,
                y:
                  69_442_595_448_928_048_809_603_412_737_824_612_252_030_373_964_082_523_340_701_998_153_322_752_075_027
              }
            }
          ]
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAFICAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAFgAUdo4e60z0IIZgM/gKzv8PlyB0SWkAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1cBE0C7U+yRe62dkGrxuocYHEi4as5aritTYFpyXKdGJWMUdvxvW67a9PLuD0d/NvWPOXDVuCc7fkl7l68uPxJcl680IRb+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMhkAdystp1YAAIABAACAAAAAgAEAAAAAAAAAARcg/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIAIgIDa3cqbbdNh1PJioJ5WN5seKszEhCfN9PgMESEJC7Oc9gYdystp1QAAIABAACAAAAAgAAAAAAAAAAAAA==",
      expected_global: %Bitcoinex.PSBT.Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "42b224669be683585854193052ef88b1efe2ee963af26c0dfe2730bfba4a7427",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 4_999_997_000,
              script_pub_key: "0014768e1eeb4cf420866033f80aceff0f9720744969"
            }
          ],
          lock_time: 0
        }
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 5_000_000_000,
            script_pub_key: "51205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757"
          },
          tap_key_sig:
            <<187, 83, 236, 145, 123, 173, 157, 144, 106, 241, 186, 135, 24, 28, 72, 184, 106,
              206, 90, 174, 43, 83, 96, 90, 114, 92, 167, 70, 37, 99, 20, 118, 252, 111, 91, 174,
              218, 244, 242, 238, 15, 71, 127, 54, 245, 143, 57, 112, 213, 184, 39, 59, 126, 73,
              123, 151, 175, 46, 63, 18, 92, 151, 175, 52>>,
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 1, 0]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  114_980_336_156_212_694_879_327_992_636_798_621_605_698_402_417_475_818_833_771_862_351_800_336_097_842,
                y:
                  80_701_412_123_039_057_594_876_775_965_687_848_606_566_558_952_919_681_215_239_681_970_556_263_873_620
              }
            }
          ],
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              114_980_336_156_212_694_879_327_992_636_798_621_605_698_402_417_475_818_833_771_862_351_800_336_097_842,
            y:
              80_701_412_123_039_057_594_876_775_965_687_848_606_566_558_952_919_681_215_239_681_970_556_263_873_620
          }
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_732, 2_147_483_649, 2_147_483_648, 0, 0]
              },
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  48_608_022_430_402_926_014_916_497_053_789_681_947_094_617_356_347_258_841_609_839_742_612_155_560_920,
                y:
                  69_442_595_448_928_048_809_603_412_737_824_612_252_030_373_964_082_523_340_701_998_153_322_752_075_027
              }
            }
          ]
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAF4CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgABBSARJNp67JLM0GyVRWJkf0N7E4uVchqEvivyJ2u92rPmcSEHESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEZAHcrLadWAACAAQAAgAAAAIAAAAAABQAAAAA=",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "42b224669be683585854193052ef88b1efe2ee963af26c0dfe2730bfba4a7427",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 4_999_997_000,
              script_pub_key:
                "512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743"
            }
          ],
          lock_time: 0
        }
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 5_000_000_000,
            script_pub_key: "51205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757"
          },
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 1, 0]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  114_980_336_156_212_694_879_327_992_636_798_621_605_698_402_417_475_818_833_771_862_351_800_336_097_842,
                y:
                  80_701_412_123_039_057_594_876_775_965_687_848_606_566_558_952_919_681_215_239_681_970_556_263_873_620
              }
            }
          ],
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              114_980_336_156_212_694_879_327_992_636_798_621_605_698_402_417_475_818_833_771_862_351_800_336_097_842,
            y:
              80_701_412_123_039_057_594_876_775_965_687_848_606_566_558_952_919_681_215_239_681_970_556_263_873_620
          }
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              7_754_432_814_978_735_047_277_584_654_213_252_760_875_963_706_567_224_418_638_150_419_547_067_508_337,
            y:
              42_423_437_181_898_177_373_695_716_172_273_752_501_072_424_002_872_139_093_103_823_791_254_979_333_346
          },
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 5]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  7_754_432_814_978_735_047_277_584_654_213_252_760_875_963_706_567_224_418_638_150_419_547_067_508_337,
                y:
                  42_423_437_181_898_177_373_695_716_172_273_752_501_072_424_002_872_139_093_103_823_791_254_979_333_346
              }
            }
          ]
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4fgjICyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSrMBCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wJfG5v6l/3FP9XJEmZkIEOQG6YqhD1v35fZ4S8HQqabOIyBDILC/FvARtT6nvmFZJKp/J+XSmtIOoRVdhIZ2w7rRsqzAYhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDNlw4V9T/AyC+VD9Vg/6kZt2FyvgFzaKiZE68HT0ALCRFfLkkK98xFxPeFEfNgV85cWlxWMlop+0TfwgPzVuH4IyD6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqazAIRYssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20jkBzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwl3Ky2nVgAAgAEAAIACAACAAAAAAAAAAAAhFkMgsL8W8BG1Pqe+YVkkqn8n5dKa0g6hFV2EhnbDutGyOQERXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+HcrLadWAACAAQAAgAEAAIAAAAAAAAAAACEWUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAFAHxGHl0hFvoPejzvOx0MCmzn0m4XraCy5cktGe+tSLQYWcuKRRypOQFvfWIFnpSXoaSiZ1admHbaYBAa/zjjUpubk5zn+RrpcHcrLadWAACAAQAAgAMAAIAAAAAAAAAAAAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAARgg8DYuL3Wm9CClvePrIh2WrmcgzyX4GJDJWx13WstRXmUAAQUgESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEhBxEk2nrskszQbJVFYmR/Q3sTi5VyGoS+K/Ina73as+ZxGQB3Ky2nVgAAgAEAAIAAAACAAAAAAAUAAAAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "2695697f810d60b5bc56eb7ff9c6f0546e5572f90120662ea7f90b236587d49b",
              prev_vout: 1,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 4_999_997_000,
              script_pub_key:
                "512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743"
            }
          ],
          lock_time: 0
        }
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 5_000_000_000,
            script_pub_key: "5120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b692"
          },
          tap_leaf_script: [
            %{
              control_block:
                <<193, 80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7,
                  138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192, 111, 125,
                  98, 5, 158, 148, 151, 161, 164, 162, 103, 86, 157, 152, 118, 218, 96, 16, 26,
                  255, 56, 227, 82, 155, 155, 147, 156, 231, 249, 26, 233, 112, 17, 95, 46, 73,
                  10, 247, 204, 69, 196, 247, 133, 17, 243, 96, 87, 206, 92, 90, 92, 86, 50, 90,
                  41, 251, 68, 223, 194, 3, 243, 86, 225, 248>>,
              leaf_version: 192,
              script: %Bitcoinex.Script{
                items: [
                  32,
                  <<44, 177, 58, 198, 130, 72, 222, 128, 106, 166, 163, 101, 156, 243, 192, 62,
                    182, 130, 29, 9, 200, 17, 74, 78, 134, 143, 235, 222, 134, 91, 182, 210>>,
                  172
                ]
              }
            },
            %{
              control_block:
                <<193, 80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7,
                  138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192, 151, 198,
                  230, 254, 165, 255, 113, 79, 245, 114, 68, 153, 153, 8, 16, 228, 6, 233, 138,
                  161, 15, 91, 247, 229, 246, 120, 75, 193, 208, 169, 166, 206>>,
              leaf_version: 192,
              script: %Bitcoinex.Script{
                items: [
                  32,
                  <<67, 32, 176, 191, 22, 240, 17, 181, 62, 167, 190, 97, 89, 36, 170, 127, 39,
                    229, 210, 154, 210, 14, 161, 21, 93, 132, 134, 118, 195, 186, 209, 178>>,
                  172
                ]
              }
            },
            %{
              control_block:
                <<193, 80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7,
                  138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192, 205, 151,
                  14, 21, 245, 63, 192, 200, 47, 149, 15, 213, 96, 255, 169, 25, 183, 97, 114,
                  190, 1, 115, 104, 168, 153, 19, 175, 7, 79, 64, 11, 9, 17, 95, 46, 73, 10, 247,
                  204, 69, 196, 247, 133, 17, 243, 96, 87, 206, 92, 90, 92, 86, 50, 90, 41, 251,
                  68, 223, 194, 3, 243, 86, 225, 248>>,
              leaf_version: 192,
              script: %Bitcoinex.Script{
                items: [
                  32,
                  <<250, 15, 122, 60, 239, 59, 29, 12, 10, 108, 231, 210, 110, 23, 173, 160, 178,
                    229, 201, 45, 25, 239, 173, 72, 180, 24, 89, 203, 138, 69, 28, 169>>,
                  172
                ]
              }
            }
          ],
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_650, 0, 0]
              },
              leaf_hashes: [
                <<205, 151, 14, 21, 245, 63, 192, 200, 47, 149, 15, 213, 96, 255, 169, 25, 183,
                  97, 114, 190, 1, 115, 104, 168, 153, 19, 175, 7, 79, 64, 11, 9>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  20_214_902_921_207_623_608_562_994_083_326_228_570_924_245_815_299_146_006_330_164_270_236_901_816_018,
                y:
                  33_295_055_140_301_703_998_324_163_407_344_732_932_777_411_489_229_368_797_248_015_921_617_797_465_334
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_649, 0, 0]
              },
              leaf_hashes: [
                <<17, 95, 46, 73, 10, 247, 204, 69, 196, 247, 133, 17, 243, 96, 87, 206, 92, 90,
                  92, 86, 50, 90, 41, 251, 68, 223, 194, 3, 243, 86, 225, 248>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  30_362_719_820_274_234_030_344_172_757_366_317_297_290_310_294_146_862_871_341_483_479_788_794_073_522,
                y:
                  61_647_782_036_840_226_561_126_690_482_215_573_260_410_436_215_868_166_657_038_664_786_860_649_378_740
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{child_nums: []},
              leaf_hashes: [],
              pfp: <<124, 70, 30, 93>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  36_444_060_476_547_731_421_425_013_472_121_489_344_383_018_981_262_552_973_668_657_287_772_036_414_144,
                y:
                  22_537_504_475_708_154_238_330_251_540_244_790_414_456_712_057_027_634_449_505_794_721_772_594_235_652
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_651, 0, 0]
              },
              leaf_hashes: [
                <<111, 125, 98, 5, 158, 148, 151, 161, 164, 162, 103, 86, 157, 152, 118, 218, 96,
                  16, 26, 255, 56, 227, 82, 155, 155, 147, 156, 231, 249, 26, 233, 112>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  113_105_558_507_633_336_913_885_034_341_920_459_137_683_993_564_483_976_665_524_654_145_797_510_995_113,
                y:
                  107_072_043_951_624_069_052_082_507_734_100_608_508_887_739_811_142_108_528_627_392_964_071_353_710_384
              }
            }
          ],
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              36_444_060_476_547_731_421_425_013_472_121_489_344_383_018_981_262_552_973_668_657_287_772_036_414_144,
            y:
              22_537_504_475_708_154_238_330_251_540_244_790_414_456_712_057_027_634_449_505_794_721_772_594_235_652
          },
          tap_merkle_root:
            <<240, 54, 46, 47, 117, 166, 244, 32, 165, 189, 227, 235, 34, 29, 150, 174, 103, 32,
              207, 37, 248, 24, 144, 201, 91, 29, 119, 90, 203, 81, 94, 101>>
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              7_754_432_814_978_735_047_277_584_654_213_252_760_875_963_706_567_224_418_638_150_419_547_067_508_337,
            y:
              42_423_437_181_898_177_373_695_716_172_273_752_501_072_424_002_872_139_093_103_823_791_254_979_333_346,
            z: 0
          },
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 5]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  7_754_432_814_978_735_047_277_584_654_213_252_760_875_963_706_567_224_418_638_150_419_547_067_508_337,
                y:
                  42_423_437_181_898_177_373_695_716_172_273_752_501_072_424_002_872_139_093_103_823_791_254_979_333_346,
                z: 0
              }
            }
          ]
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAF4CAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/////AUjmBSoBAAAAIlEgCoy9yG3hzhwPnK6yLW33ztNoP+Qj4F0eQCqHk0HW9vUAAAAAAAEBKwDyBSoBAAAAIlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1chFv40kGTJjW4qhT+jybEr2LMEoZwZXGDvp+4jkwRtP6IyGQB3Ky2nVgAAgAEAAIAAAACAAQAAAAAAAAABFyD+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMgABBSBQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wAEGbwLAIiBzblcpAP4SUliaIUPI88efcaBBLSNTr3VelwHHgmlKAqwCwCIgYxxfO1gyuPvev7GXBM7rMjwh9A96JPQ9aO8MwmsSWWmsAcAiIET6pJoDON5IjI3//s37bzKfOAvVZu8gyN9tgT6rHEJzrCEHRPqkmgM43kiMjf/+zftvMp84C9Vm7yDI322BPqscQnM5AfBreYuSoQ7ZqdC7/Trxc6U7FhfaOkFZygCCFs2Fay4Odystp1YAAIABAACAAQAAgAAAAAADAAAAIQdQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wAUAfEYeXSEHYxxfO1gyuPvev7GXBM7rMjwh9A96JPQ9aO8MwmsSWWk5ARis5AmIl4Xg6nDO67jhyokqenjq7eDy4pbPQ1lhqPTKdystp1YAAIABAACAAgAAgAAAAAADAAAAIQdzblcpAP4SUliaIUPI88efcaBBLSNTr3VelwHHgmlKAjkBKaW0kVCQFi11mv0/4Pk/ozJgVtC0CIy5M8rngmy42Cx3Ky2nVgAAgAEAAIADAACAAAAAAAMAAAAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "42b224669be683585854193052ef88b1efe2ee963af26c0dfe2730bfba4a7427",
              prev_vout: 0,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 4_999_997_000,
              script_pub_key:
                "51200a8cbdc86de1ce1c0f9caeb22d6df7ced3683fe423e05d1e402a879341d6f6f5"
            }
          ],
          lock_time: 0
        }
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 5_000_000_000,
            script_pub_key: "51205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757"
          },
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 1, 0]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  114_980_336_156_212_694_879_327_992_636_798_621_605_698_402_417_475_818_833_771_862_351_800_336_097_842,
                y:
                  80_701_412_123_039_057_594_876_775_965_687_848_606_566_558_952_919_681_215_239_681_970_556_263_873_620
              }
            }
          ],
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              114_980_336_156_212_694_879_327_992_636_798_621_605_698_402_417_475_818_833_771_862_351_800_336_097_842,
            y:
              80_701_412_123_039_057_594_876_775_965_687_848_606_566_558_952_919_681_215_239_681_970_556_263_873_620
          }
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              36_444_060_476_547_731_421_425_013_472_121_489_344_383_018_981_262_552_973_668_657_287_772_036_414_144,
            y:
              22_537_504_475_708_154_238_330_251_540_244_790_414_456_712_057_027_634_449_505_794_721_772_594_235_652
          },
          tap_tree: %{
            leaves: [
              %{
                depth: 2,
                leaf_version: 192,
                script: %Bitcoinex.Script{
                  items: [
                    32,
                    <<115, 110, 87, 41, 0, 254, 18, 82, 88, 154, 33, 67, 200, 243, 199, 159, 113,
                      160, 65, 45, 35, 83, 175, 117, 94, 151, 1, 199, 130, 105, 74, 2>>,
                    172
                  ]
                }
              },
              %{
                depth: 2,
                leaf_version: 192,
                script: %Bitcoinex.Script{
                  items: [
                    32,
                    <<99, 28, 95, 59, 88, 50, 184, 251, 222, 191, 177, 151, 4, 206, 235, 50, 60,
                      33, 244, 15, 122, 36, 244, 61, 104, 239, 12, 194, 107, 18, 89, 105>>,
                    172
                  ]
                }
              },
              %{
                depth: 1,
                leaf_version: 192,
                script: %Bitcoinex.Script{
                  items: [
                    32,
                    <<68, 250, 164, 154, 3, 56, 222, 72, 140, 141, 255, 254, 205, 251, 111, 50,
                      159, 56, 11, 213, 102, 239, 32, 200, 223, 109, 129, 62, 171, 28, 66, 115>>,
                    172
                  ]
                }
              }
            ]
          },
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_649, 0, 3]
              },
              leaf_hashes: [
                <<240, 107, 121, 139, 146, 161, 14, 217, 169, 208, 187, 253, 58, 241, 115, 165,
                  59, 22, 23, 218, 58, 65, 89, 202, 0, 130, 22, 205, 133, 107, 46, 14>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  31_200_121_508_428_702_019_893_244_742_884_023_762_479_223_940_651_285_251_383_304_714_523_995_030_131,
                y:
                  53_120_362_633_623_697_201_506_777_401_802_198_637_852_190_256_815_688_867_012_397_976_660_138_781_348,
                z: 0
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{child_nums: []},
              leaf_hashes: [],
              pfp: <<124, 70, 30, 93>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  36_444_060_476_547_731_421_425_013_472_121_489_344_383_018_981_262_552_973_668_657_287_772_036_414_144,
                y:
                  22_537_504_475_708_154_238_330_251_540_244_790_414_456_712_057_027_634_449_505_794_721_772_594_235_652
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_650, 0, 3]
              },
              leaf_hashes: [
                <<24, 172, 228, 9, 136, 151, 133, 224, 234, 112, 206, 235, 184, 225, 202, 137, 42,
                  122, 120, 234, 237, 224, 242, 226, 150, 207, 67, 89, 97, 168, 244, 202>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  44_829_100_993_385_313_407_048_989_888_172_542_182_954_521_609_934_891_498_742_790_273_562_110_482_793,
                y:
                  35_170_189_511_235_529_380_611_046_465_697_762_403_784_417_654_141_736_675_144_354_496_257_103_432_480,
                z: 0
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_651, 0, 3]
              },
              leaf_hashes: [
                <<41, 165, 180, 145, 80, 144, 22, 45, 117, 154, 253, 63, 224, 249, 63, 163, 50,
                  96, 86, 208, 180, 8, 140, 185, 51, 202, 231, 130, 108, 184, 216, 44>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  52_210_932_321_595_760_052_581_731_536_224_183_934_983_599_287_982_449_328_637_004_030_112_510_331_394,
                y:
                  77_569_177_239_768_622_921_463_492_097_741_805_392_046_359_270_612_182_587_656_363_386_108_779_135_734,
                z: 0
              }
            }
          ]
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAF4CAAAAAZvUh2UjC/mnLmYgAflyVW5U8Mb5f+tWvLVgDYF/aZUmAQAAAAD/////AUjmBSoBAAAAIlEgg2mORYxmZOFZXXXaJZfeHiLul9eY5wbEwKS1qYI810MAAAAAAAEBKwDyBSoBAAAAIlEgwiR++/2SrEf29AuNQtFpF1oZ+p+hDkol1/NetN2FtpJBFCyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwlAv4GNl1fW/+tTi6BX+0wfxOD17xhudlvrVkeR4Cr1/T1eJVHU404z2G8na4LJnHmu0/A5Wgge/NLMLGXdfmk9eUEUQyCwvxbwEbU+p75hWSSqfyfl0prSDqEVXYSGdsO60bIRXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+EDh8atvq/omsjbyGDNxncHUKKt2jYD5H5mI2KvvR7+4Y7sfKlKfdowV8AzjTsKDzcB+iPhCi+KPbvZAQ8MpEYEaQRT6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqW99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwQOwfA3kgZGHIM0IoVCMyZwirAx8NpKJT7kWq+luMkgNNi2BUkPjNE+APmJmJuX4hX6o28S3uNpPS2szzeBwXV/ZiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wG99YgWelJehpKJnVp2YdtpgEBr/OONSm5uTnOf5GulwEV8uSQr3zEXE94UR82BXzlxaXFYyWin7RN/CA/NW4fgjICyxOsaCSN6AaqajZZzzwD62gh0JyBFKToaP696GW7bSrMBCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wJfG5v6l/3FP9XJEmZkIEOQG6YqhD1v35fZ4S8HQqabOIyBDILC/FvARtT6nvmFZJKp/J+XSmtIOoRVdhIZ2w7rRsqzAYhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsDNlw4V9T/AyC+VD9Vg/6kZt2FyvgFzaKiZE68HT0ALCRFfLkkK98xFxPeFEfNgV85cWlxWMlop+0TfwgPzVuH4IyD6D3o87zsdDAps59JuF62gsuXJLRnvrUi0GFnLikUcqazAIRYssTrGgkjegGqmo2Wc88A+toIdCcgRSk6Gj+vehlu20jkBzZcOFfU/wMgvlQ/VYP+pGbdhcr4Bc2iomROvB09ACwl3Ky2nVgAAgAEAAIACAACAAAAAAAAAAAAhFkMgsL8W8BG1Pqe+YVkkqn8n5dKa0g6hFV2EhnbDutGyOQERXy5JCvfMRcT3hRHzYFfOXFpcVjJaKftE38ID81bh+HcrLadWAACAAQAAgAEAAIAAAAAAAAAAACEWUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAFAHxGHl0hFvoPejzvOx0MCmzn0m4XraCy5cktGe+tSLQYWcuKRRypOQFvfWIFnpSXoaSiZ1admHbaYBAa/zjjUpubk5zn+RrpcHcrLadWAACAAQAAgAMAAIAAAAAAAAAAAAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAARgg8DYuL3Wm9CClvePrIh2WrmcgzyX4GJDJWx13WstRXmUAAQUgESTaeuySzNBslUViZH9DexOLlXIahL4r8idrvdqz5nEhBxEk2nrskszQbJVFYmR/Q3sTi5VyGoS+K/Ina73as+ZxGQB3Ky2nVgAAgAEAAIAAAACAAAAAAAUAAAAA",
      expected_global: %Global{
        unsigned_tx: %Bitcoinex.Transaction{
          version: 2,
          inputs: [
            %Bitcoinex.Transaction.In{
              prev_txid: "2695697f810d60b5bc56eb7ff9c6f0546e5572f90120662ea7f90b236587d49b",
              prev_vout: 1,
              script_sig: "",
              sequence_no: 4_294_967_295
            }
          ],
          outputs: [
            %Bitcoinex.Transaction.Out{
              value: 4_999_997_000,
              script_pub_key:
                "512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743"
            }
          ],
          lock_time: 0
        }
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          witness_utxo: %Bitcoinex.Transaction.Out{
            value: 5_000_000_000,
            script_pub_key: "5120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b692"
          },
          tap_script_sig: [
            %{
              leaf_hash:
                <<205, 151, 14, 21, 245, 63, 192, 200, 47, 149, 15, 213, 96, 255, 169, 25, 183,
                  97, 114, 190, 1, 115, 104, 168, 153, 19, 175, 7, 79, 64, 11, 9>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  20_214_902_921_207_623_608_562_994_083_326_228_570_924_245_815_299_146_006_330_164_270_236_901_816_018,
                y:
                  33_295_055_140_301_703_998_324_163_407_344_732_932_777_411_489_229_368_797_248_015_921_617_797_465_334
              },
              signature:
                <<191, 129, 141, 151, 87, 214, 255, 235, 83, 139, 160, 87, 251, 76, 31, 196, 224,
                  245, 239, 24, 110, 118, 91, 235, 86, 71, 145, 224, 42, 245, 253, 61, 94, 37, 81,
                  212, 227, 78, 51, 216, 111, 39, 107, 130, 201, 156, 121, 174, 211, 240, 57, 90,
                  8, 30, 252, 210, 204, 44, 101, 221, 126, 105, 61, 121>>
            },
            %{
              leaf_hash:
                <<17, 95, 46, 73, 10, 247, 204, 69, 196, 247, 133, 17, 243, 96, 87, 206, 92, 90,
                  92, 86, 50, 90, 41, 251, 68, 223, 194, 3, 243, 86, 225, 248>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  30_362_719_820_274_234_030_344_172_757_366_317_297_290_310_294_146_862_871_341_483_479_788_794_073_522,
                y:
                  61_647_782_036_840_226_561_126_690_482_215_573_260_410_436_215_868_166_657_038_664_786_860_649_378_740
              },
              signature:
                <<225, 241, 171, 111, 171, 250, 38, 178, 54, 242, 24, 51, 113, 157, 193, 212, 40,
                  171, 118, 141, 128, 249, 31, 153, 136, 216, 171, 239, 71, 191, 184, 99, 187, 31,
                  42, 82, 159, 118, 140, 21, 240, 12, 227, 78, 194, 131, 205, 192, 126, 136, 248,
                  66, 139, 226, 143, 110, 246, 64, 67, 195, 41, 17, 129, 26>>
            },
            %{
              leaf_hash:
                <<111, 125, 98, 5, 158, 148, 151, 161, 164, 162, 103, 86, 157, 152, 118, 218, 96,
                  16, 26, 255, 56, 227, 82, 155, 155, 147, 156, 231, 249, 26, 233, 112>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  113_105_558_507_633_336_913_885_034_341_920_459_137_683_993_564_483_976_665_524_654_145_797_510_995_113,
                y:
                  107_072_043_951_624_069_052_082_507_734_100_608_508_887_739_811_142_108_528_627_392_964_071_353_710_384
              },
              signature:
                <<236, 31, 3, 121, 32, 100, 97, 200, 51, 66, 40, 84, 35, 50, 103, 8, 171, 3, 31,
                  13, 164, 162, 83, 238, 69, 170, 250, 91, 140, 146, 3, 77, 139, 96, 84, 144, 248,
                  205, 19, 224, 15, 152, 153, 137, 185, 126, 33, 95, 170, 54, 241, 45, 238, 54,
                  147, 210, 218, 204, 243, 120, 28, 23, 87, 246>>
            }
          ],
          tap_leaf_script: [
            %{
              control_block:
                <<193, 80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7,
                  138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192, 111, 125,
                  98, 5, 158, 148, 151, 161, 164, 162, 103, 86, 157, 152, 118, 218, 96, 16, 26,
                  255, 56, 227, 82, 155, 155, 147, 156, 231, 249, 26, 233, 112, 17, 95, 46, 73,
                  10, 247, 204, 69, 196, 247, 133, 17, 243, 96, 87, 206, 92, 90, 92, 86, 50, 90,
                  41, 251, 68, 223, 194, 3, 243, 86, 225, 248>>,
              leaf_version: 192,
              script: %Bitcoinex.Script{
                items: [
                  32,
                  <<44, 177, 58, 198, 130, 72, 222, 128, 106, 166, 163, 101, 156, 243, 192, 62,
                    182, 130, 29, 9, 200, 17, 74, 78, 134, 143, 235, 222, 134, 91, 182, 210>>,
                  172
                ]
              }
            },
            %{
              control_block:
                <<193, 80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7,
                  138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192, 151, 198,
                  230, 254, 165, 255, 113, 79, 245, 114, 68, 153, 153, 8, 16, 228, 6, 233, 138,
                  161, 15, 91, 247, 229, 246, 120, 75, 193, 208, 169, 166, 206>>,
              leaf_version: 192,
              script: %Bitcoinex.Script{
                items: [
                  32,
                  <<67, 32, 176, 191, 22, 240, 17, 181, 62, 167, 190, 97, 89, 36, 170, 127, 39,
                    229, 210, 154, 210, 14, 161, 21, 93, 132, 134, 118, 195, 186, 209, 178>>,
                  172
                ]
              }
            },
            %{
              control_block:
                <<193, 80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7,
                  138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192, 205, 151,
                  14, 21, 245, 63, 192, 200, 47, 149, 15, 213, 96, 255, 169, 25, 183, 97, 114,
                  190, 1, 115, 104, 168, 153, 19, 175, 7, 79, 64, 11, 9, 17, 95, 46, 73, 10, 247,
                  204, 69, 196, 247, 133, 17, 243, 96, 87, 206, 92, 90, 92, 86, 50, 90, 41, 251,
                  68, 223, 194, 3, 243, 86, 225, 248>>,
              leaf_version: 192,
              script: %Bitcoinex.Script{
                items: [
                  32,
                  <<250, 15, 122, 60, 239, 59, 29, 12, 10, 108, 231, 210, 110, 23, 173, 160, 178,
                    229, 201, 45, 25, 239, 173, 72, 180, 24, 89, 203, 138, 69, 28, 169>>,
                  172
                ]
              }
            }
          ],
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_650, 0, 0]
              },
              leaf_hashes: [
                <<205, 151, 14, 21, 245, 63, 192, 200, 47, 149, 15, 213, 96, 255, 169, 25, 183,
                  97, 114, 190, 1, 115, 104, 168, 153, 19, 175, 7, 79, 64, 11, 9>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  20_214_902_921_207_623_608_562_994_083_326_228_570_924_245_815_299_146_006_330_164_270_236_901_816_018,
                y:
                  33_295_055_140_301_703_998_324_163_407_344_732_932_777_411_489_229_368_797_248_015_921_617_797_465_334
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_649, 0, 0]
              },
              leaf_hashes: [
                <<17, 95, 46, 73, 10, 247, 204, 69, 196, 247, 133, 17, 243, 96, 87, 206, 92, 90,
                  92, 86, 50, 90, 41, 251, 68, 223, 194, 3, 243, 86, 225, 248>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  30_362_719_820_274_234_030_344_172_757_366_317_297_290_310_294_146_862_871_341_483_479_788_794_073_522,
                y:
                  61_647_782_036_840_226_561_126_690_482_215_573_260_410_436_215_868_166_657_038_664_786_860_649_378_740
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{child_nums: []},
              leaf_hashes: [],
              pfp: <<124, 70, 30, 93>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  36_444_060_476_547_731_421_425_013_472_121_489_344_383_018_981_262_552_973_668_657_287_772_036_414_144,
                y:
                  22_537_504_475_708_154_238_330_251_540_244_790_414_456_712_057_027_634_449_505_794_721_772_594_235_652
              }
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_651, 0, 0]
              },
              leaf_hashes: [
                <<111, 125, 98, 5, 158, 148, 151, 161, 164, 162, 103, 86, 157, 152, 118, 218, 96,
                  16, 26, 255, 56, 227, 82, 155, 155, 147, 156, 231, 249, 26, 233, 112>>
              ],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  113_105_558_507_633_336_913_885_034_341_920_459_137_683_993_564_483_976_665_524_654_145_797_510_995_113,
                y:
                  107_072_043_951_624_069_052_082_507_734_100_608_508_887_739_811_142_108_528_627_392_964_071_353_710_384
              }
            }
          ],
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              36_444_060_476_547_731_421_425_013_472_121_489_344_383_018_981_262_552_973_668_657_287_772_036_414_144,
            y:
              22_537_504_475_708_154_238_330_251_540_244_790_414_456_712_057_027_634_449_505_794_721_772_594_235_652
          },
          tap_merkle_root:
            <<240, 54, 46, 47, 117, 166, 244, 32, 165, 189, 227, 235, 34, 29, 150, 174, 103, 32,
              207, 37, 248, 24, 144, 201, 91, 29, 119, 90, 203, 81, 94, 101>>
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          tap_internal_key: %Bitcoinex.Secp256k1.Point{
            x:
              7_754_432_814_978_735_047_277_584_654_213_252_760_875_963_706_567_224_418_638_150_419_547_067_508_337,
            y:
              42_423_437_181_898_177_373_695_716_172_273_752_501_072_424_002_872_139_093_103_823_791_254_979_333_346,
            z: 0
          },
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 5]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              public_key: %Bitcoinex.Secp256k1.Point{
                x:
                  7_754_432_814_978_735_047_277_584_654_213_252_760_875_963_706_567_224_418_638_150_419_547_067_508_337,
                y:
                  42_423_437_181_898_177_373_695_716_172_273_752_501_072_424_002_872_139_093_103_823_791_254_979_333_346,
                z: 0
              }
            }
          ]
        }
      ]
    }
  ]

  describe "decode/1" do
    test "valid psbts" do
      for valid_psbt <- @valid_psbts do
        case PSBT.decode(valid_psbt.psbt) do
          {:ok, psbt} ->
            assert valid_psbt.expected_global == psbt.global
            assert valid_psbt.expected_in == psbt.inputs
            assert valid_psbt.expected_out == psbt.outputs
            assert valid_psbt.psbt == PSBT.encode_b64(psbt)

          {:error, _} ->
            assert :error != :error
        end
      end
    end
  end

  describe "to_file/2 & from_file/1" do
    test "valid psbts" do
      filename = "./test/psbt-test.psbt"

      for valid_psbt <- @valid_psbts do
        case PSBT.decode(valid_psbt.psbt) do
          {:ok, psbt_in} ->
            PSBT.to_file(psbt_in, filename)
            {res, psbt_out} = PSBT.from_file(filename)
            assert res == :ok
            assert valid_psbt.expected_global == psbt_out.global
            assert valid_psbt.expected_in == psbt_out.inputs
            assert valid_psbt.expected_out == psbt_out.outputs
            assert valid_psbt.psbt == PSBT.encode_b64(psbt_out)

          {:error, _} ->
            assert false
        end
      end

      File.rm_rf(filename)
    end
  end
end
