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
          final_scriptsig:
            "47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292"
        },
        %In{
          redeem_script: "001485d13537f2e265405a34dbafa9e3dda01fb82308",
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
              public_key: "029da12cdb5b235692b91536afefe5c91c3ab9473d8e43b533836ab456299c8871",
              pfp: <<217, 12, 106, 79>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_822, 2_147_483_649, 0]
              },
              public_key: "03372b34234ed7cf9c1fea5d05d441557927be9542b162eb02e1ab2ce80224c00b",
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
              public_key: "039eff1f547a1d5f92dfa2ba7af6ac971a4bd03ba4a734b03156a256b8ad3a1ef9",
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
              public_key: "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
              pfp: <<180, 166, 186, 103>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_648, 2_147_483_653]
              },
              public_key: "03de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd",
              pfp: <<180, 166, 186, 103>>
            }
          ],
          partial_sig: [
            %{
              public_key: "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
              signature:
                "304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01"
            }
          ],
          redeem_script: "0020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681",
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
              public_key: "023e1a92f74483a4c12a196d6c0253ac589cfadd5964ff3e6c63aef5d577051ed4",
              pfp: <<0, 0, 0, 0>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_650, 2, 0, 0, 1, 13]
              },
              public_key: "024d0e39b33ab57782a98fd06a7d0653385e509ee3b74dc45559e6db6391d31378",
              pfp: <<0, 0, 0, 0>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_648, 2_147_483_650, 2, 0, 0, 1, 13]
              },
              public_key: "036c0bae6bcb02e47c857c480ed1d23888c8ad6a66b83ab111cb6b9242afb1c725",
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
          redeem_script: "001485d13537f2e265405a34dbafa9e3dda01fb82308"
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
              public_key: "02ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e99"
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
              public_key: "0394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d05"
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
              public_key: "03309680f33c7de38ea6a47cd4ecd66f1f5a49747c6ffb8808ed09039243e3ad5c",
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
              public_key: "03309680f33c7de38ea6a47cd4ecd66f1f5a49747c6ffb8808ed09039243e3ad5c"
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
              public_key: "02c777161f73d0b7c72b9ee7bde650293d13f095bc7656ad1f525da5fd2e10b110",
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
              public_key: "02c777161f73d0b7c72b9ee7bde650293d13f095bc7656ad1f525da5fd2e10b110"
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
              public_key: "02d20ca502ee289686d21815bd43a80637b0698e1fbcdbe4caed445f6c1a0a90ef"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              public_key: "02d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab792"
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
              public_key: "02e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b340"
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
              pubkey:
                <<254, 52, 144, 100, 201, 141, 110, 42, 133, 63, 163, 201, 177, 43, 216, 179, 4,
                  161, 156, 25, 92, 96, 239, 167, 238, 35, 147, 4, 109, 63, 162, 50>>
            }
          ],
          tap_internal_key:
            <<254, 52, 144, 100, 201, 141, 110, 42, 133, 63, 163, 201, 177, 43, 216, 179, 4, 161,
              156, 25, 92, 96, 239, 167, 238, 35, 147, 4, 109, 63, 162, 50>>
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
              public_key: "036b772a6db74d8753c98a827958de6c78ab3312109f37d3e0304484242ece73d8"
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
              pubkey:
                <<254, 52, 144, 100, 201, 141, 110, 42, 133, 63, 163, 201, 177, 43, 216, 179, 4,
                  161, 156, 25, 92, 96, 239, 167, 238, 35, 147, 4, 109, 63, 162, 50>>
            }
          ],
          tap_internal_key:
            <<254, 52, 144, 100, 201, 141, 110, 42, 133, 63, 163, 201, 177, 43, 216, 179, 4, 161,
              156, 25, 92, 96, 239, 167, 238, 35, 147, 4, 109, 63, 162, 50>>
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
              public_key: "036b772a6db74d8753c98a827958de6c78ab3312109f37d3e0304484242ece73d8"
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
              pubkey:
                <<254, 52, 144, 100, 201, 141, 110, 42, 133, 63, 163, 201, 177, 43, 216, 179, 4,
                  161, 156, 25, 92, 96, 239, 167, 238, 35, 147, 4, 109, 63, 162, 50>>
            }
          ],
          tap_internal_key:
            <<254, 52, 144, 100, 201, 141, 110, 42, 133, 63, 163, 201, 177, 43, 216, 179, 4, 161,
              156, 25, 92, 96, 239, 167, 238, 35, 147, 4, 109, 63, 162, 50>>
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          tap_internal_key:
            <<17, 36, 218, 122, 236, 146, 204, 208, 108, 149, 69, 98, 100, 127, 67, 123, 19, 139,
              149, 114, 26, 132, 190, 43, 242, 39, 107, 189, 218, 179, 230, 113>>,
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 5]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              pubkey:
                <<17, 36, 218, 122, 236, 146, 204, 208, 108, 149, 69, 98, 100, 127, 67, 123, 19,
                  139, 149, 114, 26, 132, 190, 43, 242, 39, 107, 189, 218, 179, 230, 113>>
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
              pubkey:
                <<44, 177, 58, 198, 130, 72, 222, 128, 106, 166, 163, 101, 156, 243, 192, 62, 182,
                  130, 29, 9, 200, 17, 74, 78, 134, 143, 235, 222, 134, 91, 182, 210>>
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
              pubkey:
                <<67, 32, 176, 191, 22, 240, 17, 181, 62, 167, 190, 97, 89, 36, 170, 127, 39, 229,
                  210, 154, 210, 14, 161, 21, 93, 132, 134, 118, 195, 186, 209, 178>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{child_nums: []},
              leaf_hashes: [],
              pfp: <<124, 70, 30, 93>>,
              pubkey:
                <<80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138,
                  90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192>>
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
              pubkey:
                <<250, 15, 122, 60, 239, 59, 29, 12, 10, 108, 231, 210, 110, 23, 173, 160, 178,
                  229, 201, 45, 25, 239, 173, 72, 180, 24, 89, 203, 138, 69, 28, 169>>
            }
          ],
          tap_internal_key:
            <<80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138, 90,
              15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192>>,
          tap_merkle_root:
            <<240, 54, 46, 47, 117, 166, 244, 32, 165, 189, 227, 235, 34, 29, 150, 174, 103, 32,
              207, 37, 248, 24, 144, 201, 91, 29, 119, 90, 203, 81, 94, 101>>
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          tap_internal_key:
            <<17, 36, 218, 122, 236, 146, 204, 208, 108, 149, 69, 98, 100, 127, 67, 123, 19, 139,
              149, 114, 26, 132, 190, 43, 242, 39, 107, 189, 218, 179, 230, 113>>,
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 5]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              pubkey:
                <<17, 36, 218, 122, 236, 146, 204, 208, 108, 149, 69, 98, 100, 127, 67, 123, 19,
                  139, 149, 114, 26, 132, 190, 43, 242, 39, 107, 189, 218, 179, 230, 113>>
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
              pubkey:
                <<254, 52, 144, 100, 201, 141, 110, 42, 133, 63, 163, 201, 177, 43, 216, 179, 4,
                  161, 156, 25, 92, 96, 239, 167, 238, 35, 147, 4, 109, 63, 162, 50>>
            }
          ],
          tap_internal_key:
            <<254, 52, 144, 100, 201, 141, 110, 42, 133, 63, 163, 201, 177, 43, 216, 179, 4, 161,
              156, 25, 92, 96, 239, 167, 238, 35, 147, 4, 109, 63, 162, 50>>
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          tap_internal_key:
            <<80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138, 90,
              15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192>>,
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
              pubkey:
                <<68, 250, 164, 154, 3, 56, 222, 72, 140, 141, 255, 254, 205, 251, 111, 50, 159,
                  56, 11, 213, 102, 239, 32, 200, 223, 109, 129, 62, 171, 28, 66, 115>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{child_nums: []},
              leaf_hashes: [],
              pfp: <<124, 70, 30, 93>>,
              pubkey:
                <<80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138,
                  90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192>>
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
              pubkey:
                <<99, 28, 95, 59, 88, 50, 184, 251, 222, 191, 177, 151, 4, 206, 235, 50, 60, 33,
                  244, 15, 122, 36, 244, 61, 104, 239, 12, 194, 107, 18, 89, 105>>
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
              pubkey:
                <<115, 110, 87, 41, 0, 254, 18, 82, 88, 154, 33, 67, 200, 243, 199, 159, 113, 160,
                  65, 45, 35, 83, 175, 117, 94, 151, 1, 199, 130, 105, 74, 2>>
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
              pubkey:
                <<44, 177, 58, 198, 130, 72, 222, 128, 106, 166, 163, 101, 156, 243, 192, 62, 182,
                  130, 29, 9, 200, 17, 74, 78, 134, 143, 235, 222, 134, 91, 182, 210>>,
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
              pubkey:
                <<67, 32, 176, 191, 22, 240, 17, 181, 62, 167, 190, 97, 89, 36, 170, 127, 39, 229,
                  210, 154, 210, 14, 161, 21, 93, 132, 134, 118, 195, 186, 209, 178>>,
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
              pubkey:
                <<250, 15, 122, 60, 239, 59, 29, 12, 10, 108, 231, 210, 110, 23, 173, 160, 178,
                  229, 201, 45, 25, 239, 173, 72, 180, 24, 89, 203, 138, 69, 28, 169>>,
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
              pubkey:
                <<44, 177, 58, 198, 130, 72, 222, 128, 106, 166, 163, 101, 156, 243, 192, 62, 182,
                  130, 29, 9, 200, 17, 74, 78, 134, 143, 235, 222, 134, 91, 182, 210>>
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
              pubkey:
                <<67, 32, 176, 191, 22, 240, 17, 181, 62, 167, 190, 97, 89, 36, 170, 127, 39, 229,
                  210, 154, 210, 14, 161, 21, 93, 132, 134, 118, 195, 186, 209, 178>>
            },
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{child_nums: []},
              leaf_hashes: [],
              pfp: <<124, 70, 30, 93>>,
              pubkey:
                <<80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138,
                  90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192>>
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
              pubkey:
                <<250, 15, 122, 60, 239, 59, 29, 12, 10, 108, 231, 210, 110, 23, 173, 160, 178,
                  229, 201, 45, 25, 239, 173, 72, 180, 24, 89, 203, 138, 69, 28, 169>>
            }
          ],
          tap_internal_key:
            <<80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138, 90,
              15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192>>,
          tap_merkle_root:
            <<240, 54, 46, 47, 117, 166, 244, 32, 165, 189, 227, 235, 34, 29, 150, 174, 103, 32,
              207, 37, 248, 24, 144, 201, 91, 29, 119, 90, 203, 81, 94, 101>>
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          tap_internal_key:
            <<17, 36, 218, 122, 236, 146, 204, 208, 108, 149, 69, 98, 100, 127, 67, 123, 19, 139,
              149, 114, 26, 132, 190, 43, 242, 39, 107, 189, 218, 179, 230, 113>>,
          tap_bip32_derivation: [
            %{
              derivation: %Bitcoinex.ExtendedKey.DerivationPath{
                child_nums: [2_147_483_734, 2_147_483_649, 2_147_483_648, 0, 5]
              },
              leaf_hashes: [],
              pfp: <<119, 43, 45, 167>>,
              pubkey:
                <<17, 36, 218, 122, 236, 146, 204, 208, 108, 149, 69, 98, 100, 127, 67, 123, 19,
                  139, 149, 114, 26, 132, 190, 43, 242, 39, 107, 189, 218, 179, 230, 113>>
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
