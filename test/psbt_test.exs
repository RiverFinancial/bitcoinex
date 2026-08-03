defmodule Bitcoinex.PSBTTest do
  use ExUnit.Case
  use ExUnitProperties
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
        %Bitcoinex.PSBT.Out{
          bip32_derivation: nil,
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: nil,
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
        }
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
          version: 2,
          witnesses: nil
        }
      },
      expected_in: [
        %In{
          bip32_derivation: nil,
          final_scriptsig:
            "47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292",
          final_scriptwitness: nil,
          non_witness_utxo: nil,
          partial_sig: nil,
          por_commitment: nil,
          proprietary: nil,
          redeem_script: nil,
          sighash_type: nil,
          witness_script: nil,
          witness_utxo: nil
        },
        %In{
          bip32_derivation: nil,
          final_scriptsig: nil,
          final_scriptwitness: nil,
          non_witness_utxo: nil,
          partial_sig: nil,
          por_commitment: nil,
          proprietary: nil,
          redeem_script: "001485d13537f2e265405a34dbafa9e3dda01fb82308",
          sighash_type: nil,
          witness_script: nil,
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key: "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
            value: 100_000_000
          }
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: nil,
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: nil,
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA",
      expected_global: %Global{
        proprietary: nil,
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
          version: 2,
          witnesses: nil
        },
        version: nil,
        xpub: [
          %{
            derivation: [2_147_483_822, 2_147_483_648],
            master_pfp: 1_332_350_169,
            xpub:
              "tpubDBkJeJo2X94Yq3RVz65DoUgyLUkaDrkfyrn2VcgyCRSKCRonvKvCF2FpYDGJWDkdRHBajXJGpc63GnumUt63ySvqCu2XaTRGVTKMYGuFk9H"
          },
          %{
            derivation: [2_147_483_822, 2_147_483_649],
            master_pfp: 1_332_350_169,
            xpub:
              "tpubDBkJeJo2X94YsvtBEU1eKoibEWiNv51nW5iHhs6VZp59jsE6nen8KZMFyGHuGbCvqjRqirgeMcfpVBkttpUUT6brm4duzSGoZeTbhqCNUu6"
          }
        ]
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          bip32_derivation: [
            %{
              derivation: [2_147_483_822, 2_147_483_648, 0],
              public_key: "029da12cdb5b235692b91536afefe5c91c3ab9473d8e43b533836ab456299c8871",
              pfp: 1_332_350_169
            },
            %{
              derivation: [2_147_483_822, 2_147_483_649, 0],
              public_key: "03372b34234ed7cf9c1fea5d05d441557927be9542b162eb02e1ab2ce80224c00b",
              pfp: 1_332_350_169
            }
          ],
          final_scriptsig: nil,
          final_scriptwitness: nil,
          non_witness_utxo: nil,
          partial_sig: nil,
          por_commitment: nil,
          proprietary: nil,
          redeem_script: nil,
          sighash_type: nil,
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
              derivation: [2_147_483_648, 2_147_483_648, 2_147_483_649],
              public_key: "039eff1f547a1d5f92dfa2ba7af6ac971a4bd03ba4a734b03156a256b8ad3a1ef9",
              pfp: 3_311_199_469
            }
          ],
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
        }
      ]
    },
    %{
      psbt:
        "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=",
      expected_global: %Global{
        proprietary: nil,
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
          version: 2,
          witnesses: nil
        },
        version: nil,
        xpub: nil
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          bip32_derivation: [
            %{
              derivation: [2_147_483_648, 2_147_483_648, 2_147_483_652],
              public_key: "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
              pfp: 1_740_285_620
            },
            %{
              derivation: [2_147_483_648, 2_147_483_648, 2_147_483_653],
              public_key: "03de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd",
              pfp: 1_740_285_620
            }
          ],
          final_scriptsig: nil,
          final_scriptwitness: nil,
          non_witness_utxo: nil,
          partial_sig: [
            %{
              public_key: "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
              signature:
                "304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01"
            }
          ],
          por_commitment: nil,
          proprietary: nil,
          redeem_script: "0020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681",
          sighash_type: nil,
          witness_script:
            "522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae",
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key: "a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87",
            value: 199_909_013
          }
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: nil,
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
        }
      ]
    },
    %{
      # finalized psbt
      psbt:
        "cHNidP8BAKcBAAAAAjHC7gs4NF4rUOrlta+j+wB8UHTEuLn0XY6FDUcGybQMAAAAAAD+////NUUKTkDqBbL9oqrAIk9199/ZANXi/8XEgguqQY8iiewAAAAAAP7///8CdImYAAAAAAAiACCs+u6eefBEoqCFYVWhxscCwh/WJZ+286/E8zNH9gRhd4CWmAAAAAAAF6kUV3ZMSDpAgQZkllBPVNL5uRPlwOOHAAAAAAABASuAlpgAAAAAACIAIDH8Jza8S0T6nWkCcU5GqgwxJ2rGEgWFgDSGiJVFJ5W0AQj9/QAEAEgwRQIhALL4SZucnmwtsJ2BguTQkajOkbvRTRcIMF2B/c26pnZDAiAwNPAWsW3b3PxNXZouG43Z2HJ4WufvpjM0x+VlprgFUAFHMEQCIGV66oyrbw0b9HXA8EeGKrIi88YhTGuhpQKdDxX1VivPAiAcxSrameybDohX8yINx2t452PyyqP6qUiTUMNnoAv+twFpUiECZ3pcsDl1tPNTASW/gFEm/PlWLEnQJN5h32F5qmC2U6AhA1fyyfYB3ma7Vg6JKICdCsQFD7/IchNleJnjTaTGbCFgIQP8V/0ULlUTx5q8mJ6eJh6GaCHkHXDkTnmFbpZRGDsQVVOuAAEBK4CWmAAAAAAAIgAgi3WHXCAbeRTULI6EPlb3Z3+J153IX4zK5bHRsqnrSO4BCPwEAEcwRAIgelTwDK+TOYwP6luGb5htloRgijKLoLmNrjk9imXolaICIFQ9Rq0MrOGcrYHC6BZIyyz+tB0Lm8FhqnARl7R+TpyaAUcwRAIgfHNbxYLcTt1yWeADHyo5ye4jtApn+YTgFzK16IsOW0QCIDcOnv2QYaZlc0etz9kfIrkpoepeTndtvEREKROzqqlCAWlSIQIIPVGeoWYEHRGxyDhpzTqE0uBZIjBj5DDXgBX5QWwecCECL5C1pXxiQ5uiuhZASuHYEUq+gXmXqE+wxPnV590o+HAhA0odK6A98KAdcHcI5pcbNfwR1oq0PsofJzNfvSKkdqCMU64AAQFpUiECPhqS90SDpMEqGW1sAlOsWJz63Vlk/z5sY6711XcFHtQhAk0OObM6tXeCqY/Qan0GUzheUJ7jt03EVVnm22OR0xN4IQNsC65rywLkfIV8SA7R0jiIyK1qZrg6sRHLa5JCr7HHJVOuIgICPhqS90SDpMEqGW1sAlOsWJz63Vlk/z5sY6711XcFHtQgAAAAAAAAAIACAACAAgAAAAAAAAAAAAAAAQAAAA0AAAAiAgJNDjmzOrV3gqmP0Gp9BlM4XlCe47dNxFVZ5ttjkdMTeCAAAAAAAAAAgAIAAIACAAAAAAAAAAAAAAABAAAADQAAACICA2wLrmvLAuR8hXxIDtHSOIjIrWpmuDqxEctrkkKvscclIAAAAAAAAACAAgAAgAIAAAAAAAAAAAAAAAEAAAANAAAAAAA=",
      expected_global: %Global{
        proprietary: nil,
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
          version: 1,
          witnesses: nil
        },
        version: nil,
        xpub: nil
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          bip32_derivation: nil,
          final_scriptsig: nil,
          final_scriptwitness: %Bitcoinex.Transaction.Witness{
            txinwitness: [
              "",
              "3045022100b2f8499b9c9e6c2db09d8182e4d091a8ce91bbd14d1708305d81fdcdbaa6764302203034f016b16ddbdcfc4d5d9a2e1b8dd9d872785ae7efa63334c7e565a6b8055001",
              "30440220657aea8cab6f0d1bf475c0f047862ab222f3c6214c6ba1a5029d0f15f5562bcf02201cc52ada99ec9b0e8857f3220dc76b78e763f2caa3faa9489350c367a00bfeb701",
              "522102677a5cb03975b4f3530125bf805126fcf9562c49d024de61df6179aa60b653a0210357f2c9f601de66bb560e8928809d0ac4050fbfc87213657899e34da4c66c21602103fc57fd142e5513c79abc989e9e261e866821e41d70e44e79856e9651183b105553ae"
            ]
          },
          non_witness_utxo: nil,
          partial_sig: nil,
          por_commitment: nil,
          proprietary: nil,
          redeem_script: nil,
          sighash_type: nil,
          witness_script: nil,
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key:
              "002031fc2736bc4b44fa9d6902714e46aa0c31276ac61205858034868895452795b4",
            value: 10_000_000
          }
        },
        %Bitcoinex.PSBT.In{
          bip32_derivation: nil,
          final_scriptsig: nil,
          final_scriptwitness: %Bitcoinex.Transaction.Witness{
            txinwitness: [
              "",
              "304402207a54f00caf93398c0fea5b866f986d9684608a328ba0b98dae393d8a65e895a20220543d46ad0cace19cad81c2e81648cb2cfeb41d0b9bc161aa701197b47e4e9c9a01",
              "304402207c735bc582dc4edd7259e0031f2a39c9ee23b40a67f984e01732b5e88b0e5b440220370e9efd9061a6657347adcfd91f22b929a1ea5e4e776dbc44442913b3aaa94201",
              "522102083d519ea166041d11b1c83869cd3a84d2e059223063e430d78015f9416c1e7021022f90b5a57c62439ba2ba16404ae1d8114abe817997a84fb0c4f9d5e7dd28f87021034a1d2ba03df0a01d707708e6971b35fc11d68ab43eca1f27335fbd22a476a08c53ae"
            ]
          },
          non_witness_utxo: nil,
          partial_sig: nil,
          por_commitment: nil,
          proprietary: nil,
          redeem_script: nil,
          sighash_type: nil,
          witness_script: nil,
          witness_utxo: %Bitcoinex.Transaction.Out{
            script_pub_key:
              "00208b75875c201b7914d42c8e843e56f7677f89d79dc85f8ccae5b1d1b2a9eb48ee",
            value: 10_000_000
          }
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: [
            %{
              derivation: [2_147_483_648, 2_147_483_650, 2, 0, 0, 1, 13],
              public_key: "023e1a92f74483a4c12a196d6c0253ac589cfadd5964ff3e6c63aef5d577051ed4",
              pfp: 0
            },
            %{
              derivation: [2_147_483_648, 2_147_483_650, 2, 0, 0, 1, 13],
              public_key: "024d0e39b33ab57782a98fd06a7d0653385e509ee3b74dc45559e6db6391d31378",
              pfp: 0
            },
            %{
              derivation: [2_147_483_648, 2_147_483_650, 2, 0, 0, 1, 13],
              public_key: "036c0bae6bcb02e47c857c480ed1d23888c8ad6a66b83ab111cb6b9242afb1c725",
              pfp: 0
            }
          ],
          proprietary: nil,
          redeem_script: nil,
          witness_script:
            "5221023e1a92f74483a4c12a196d6c0253ac589cfadd5964ff3e6c63aef5d577051ed421024d0e39b33ab57782a98fd06a7d0653385e509ee3b74dc45559e6db6391d3137821036c0bae6bcb02e47c857c480ed1d23888c8ad6a66b83ab111cb6b9242afb1c72553ae"
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: nil,
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
        }
      ]
    },
    %{
      psbt: "cHNidP8BAAoAAAAAAAAAAAAAAA==",
      expected_global: %Global{
        proprietary: nil,
        unsigned_tx: %Bitcoinex.Transaction{
          inputs: [],
          lock_time: 0,
          outputs: [],
          witnesses: nil,
          version: 0
        },
        version: nil,
        xpub: nil
      },
      expected_in: [],
      expected_out: []
    },
    %{
      psbt:
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQMEAQAAAAAAAA==",
      expected_global: %Global{
        proprietary: nil,
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
          witnesses: nil,
          version: 2
        },
        version: nil,
        xpub: nil
      },
      expected_in: [
        %Bitcoinex.PSBT.In{
          bip32_derivation: nil,
          final_scriptsig: nil,
          final_scriptwitness: nil,
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
          },
          partial_sig: nil,
          por_commitment: nil,
          proprietary: nil,
          redeem_script: nil,
          sighash_type: <<1, 0, 0, 0>>,
          witness_script: nil,
          witness_utxo: nil
        }
      ],
      expected_out: [
        %Bitcoinex.PSBT.Out{
          bip32_derivation: nil,
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
        },
        %Bitcoinex.PSBT.Out{
          bip32_derivation: nil,
          proprietary: nil,
          redeem_script: nil,
          witness_script: nil
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

  # Official BIP-174 test vectors (valid). Every one must decode and re-encode
  # to the exact same bytes (lossless round-trip).
  @bip174_valid_vectors [
    "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",
    "cHNidP8BAAoAAAAAAAAAAAAAAA==",
    "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YCIfDnNSrSIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=",
    "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA=",
    "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
  ]

  # Official BIP-174 test vectors (invalid). Each must be rejected by decode/1.
  @bip174_invalid_vectors [
    {"Network transaction, not PSBT format",
     "AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA=="},
    {"PSBT missing outputs",
     "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA=="},
    {"PSBT where one input has a filled scriptSig in the unsigned tx",
     "cHNidP8BAP0KAQIAAAACqwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QAAAAAakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpL+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAABASAA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHhwEEFgAUhdE1N/LiZUBaNNuvqePdoB+4IwgAAAA="},
    {"PSBT where inputs and outputs are provided but without an unsigned tx",
     "cHNidP8AAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA=="},
    {"PSBT with duplicate keys in an input",
     "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQA/AgAAAAH//////////////////////////////////////////wAAAAAA/////wEAAAAAAAAAAANqAQAAAAAAAAAA"},
    {"PSBT with invalid global transaction typed key",
     "cHNidP8CAAFVAgAAAAEnmiMjpd+1H8RfIg+liw/BPh4zQnkqhdfjbNYzO1y8OQAAAAAA/////wGgWuoLAAAAABl2qRT/6cAGEJfMO2NvLLBGD6T8Qn0rRYisAAAAAAABASCVXuoLAAAAABepFGNFIA9o0YnhrcDfHE0W6o8UwNvrhyICA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GRjBDAiAEJLWO/6qmlOFVnqXJO7/UqJBkIkBVzfBwtncUaUQtBwIfXI6w/qZRbWC4rLM61k7eYOh4W/s6qUuZvfhhUduamgEBBCIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA"},
    {"PSBT with invalid input witness utxo typed key",
     "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAIBACCVXuoLAAAAABepFGNFIA9o0YnhrcDfHE0W6o8UwNvrhyICA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GRjBDAiAEJLWO/6qmlOFVnqXJO7/UqJBkIkBVzfBwtncUaUQtBwIfXI6w/qZRbWC4rLM61k7eYOh4W/s6qUuZvfhhUduamgEBBCIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA"},
    {"PSBT with invalid pubkey length for input partial signature typed key",
     "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIQIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYwQwIgBCS1jv+qppThVZ6lyTu/1KiQZCJAVc3wcLZ3FGlELQcCH1yOsP6mUW1guKyzOtZO3mDoeFv7OqlLmb34YVHbmpoBAQQiACB3H9GK1FlmbdSfPVZOPbxC9MhHdONgraFoFqjtSI1WgQEFR1IhA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GIQPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvVKuIgYDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYQtKa6ZwAAAIAAAACABAAAgCIGA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9ELSmumcAAACAAAAAgAUAAIAAAA=="},
    {"PSBT with invalid redeemscript typed key",
     "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQIEACIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA"},
    {"PSBT with invalid witnessscript typed key",
     "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoECBQBHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA"},
    {"PSBT with invalid pubkey in input BIP 32 derivation paths typed key",
     "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriEGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb0QtKa6ZwAAAIAAAACABAAAgCIGA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9ELSmumcAAACAAAAAgAUAAIAAAA=="},
    {"PSBT with invalid non-witness utxo typed key",
     "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAIAALsCAAAAAarXOTEBi9JfhK5AC2iEi+CdtwbqwqwYKYur7nGrZW+LAAAAAEhHMEQCIFj2/HxqM+GzFUjUgcgmwBW9MBNarULNZ3kNq2bSrSQ7AiBKHO0mBMZzW2OT5bQWkd14sA8MWUL7n3UYVvqpOBV9ugH+////AoDw+gIAAAAAF6kUD7lGNCFpa4LIM68kHHjBfdveSTSH0PIKJwEAAAAXqRQpynT4oI+BmZQoGFyXtdhS5AY/YYdlAAAAAQfaAEcwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAUgwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gFHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4AAQEgAMLrCwAAAAAXqRS39fr0Dj1ApaRZsds1NfK3L6kh6IcBByMiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEI2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="},
    {"PSBT with invalid final scriptsig typed key",
     "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAACBwDaAEcwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAUgwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gFHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4AAQEgAMLrCwAAAAAXqRS39fr0Dj1ApaRZsds1NfK3L6kh6IcBByMiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEI2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="},
    {"PSBT with invalid final script witness typed key",
     "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAggA2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="},
    {"PSBT with invalid pubkey in output BIP 32 derivation paths typed key",
     "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIQIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1PtnuylhxDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"},
    {"PSBT with invalid input sighash type typed key",
     "cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wCAwABAAAAAAEAFgAUYunpgv/zTdgjlhAxawkM0qO3R8sAAQAiACCHa62DLx0WgBXtQSMqnqZaGBXZ7xPA74dZ9ktbKyeKZQEBJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnSvVf4qHUa4A"},
    {"PSBT with invalid output redeemScript typed key",
     "cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wAAgAAFgAUYunpgv/zTdgjlhAxawkM0qO3R8sAAQAiACCHa62DLx0WgBXtQSMqnqZaGBXZ7xPA74dZ9ktbKyeKZQEBJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnSvVf4qHUa4A"},
    {"PSBT with invalid output witnessScript typed key",
     "cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wAAQAWABRi6emC//NN2COWEDFrCQzSo7dHywABACIAIIdrrYMvHRaAFe1BIyqeploYFdnvE8Dvh1n2S1srJ4plIQEAJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnQbVf4qHUa4A"},
    {"PSBT with unsigned tx serialized with witness serialization format",
     "cHNidP8BAHgCAAAAAAEBJoFxNx7f8oXpN63upLN7eAAMBWbLs61kZBcTykIXG/YAAAAAAP7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHALMuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA"},
    {"PSBT with an invalid value data due to its size being not the stated size",
     "cHNidP8BADN0Af8HAAEAAAABAP8BAApzMXQo/wAAAAAB/wEDAQAAAQAAAAAAAAAAdgEAAABBAAkAAAAAAA=="}
  ]

  # Synthetic vector exercising the v0 fields absent from the official vectors:
  # global version/proprietary/unknown, input por_commitment, the four hash
  # preimage fields, and input/output proprietary/unknown records.
  @new_fields_vector "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AegDAAAAAAAAAAAAAAAB+wQCAAAABfxwcm9wCmdsb2JhbHByb3AEd3Vuaw1nbG9iYWx1bmtub3duAAEJFnBvci1jb21taXRtZW50LW1lc3NhZ2UVCs3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3ND3JpcGVtZC1wcmVpbWFnZSELq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6sPc2hhMjU2LXByZWltYWdlFQzNzc3Nzc3Nzc3Nzc3Nzc3Nzc3NzRBoYXNoMTYwLXByZWltYWdlIQ2rq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqxBoYXNoMjU2LXByZWltYWdlA/xpcAlpbnB1dHByb3ADmWl1DGlucHV0dW5rbm93bgAD/G9wCm91dHB1dHByb3ADiG91DW91dHB1dHVua25vd24A"

  describe "BIP-174 official vectors" do
    test "all valid vectors decode and round-trip losslessly" do
      for base64 <- @bip174_valid_vectors do
        assert {:ok, psbt} = PSBT.decode(base64)
        assert PSBT.encode_b64(psbt) == base64
      end
    end

    test "all invalid vectors are rejected" do
      for {name, base64} <- @bip174_invalid_vectors do
        assert {:error, _reason} = PSBT.decode(base64), "expected error decoding: #{name}"
      end
    end

    test "duplicate keys are rejected with :duplicate_key" do
      {_name, base64} =
        Enum.find(@bip174_invalid_vectors, fn {name, _} -> name =~ "duplicate keys" end)

      assert {:error, :duplicate_key} = PSBT.decode(base64)
    end

    test "trailing bytes after the output maps are rejected" do
      {:ok, valid_bytes} = Base.decode64(hd(@bip174_valid_vectors))
      tampered = Base.encode64(valid_bytes <> <<0xFF>>)
      assert {:error, :trailing_bytes} = PSBT.decode(tampered)
    end
  end

  describe "v0 fields absent from official vectors" do
    setup do
      assert {:ok, psbt} = PSBT.decode(@new_fields_vector)
      %{psbt: psbt}
    end

    test "round-trips losslessly", %{psbt: psbt} do
      assert PSBT.encode_b64(psbt) == @new_fields_vector
    end

    test "parses global version, proprietary, and unknown records", %{psbt: psbt} do
      assert psbt.global.version == <<2, 0, 0, 0>>
      assert psbt.global.proprietary == [%{key: <<0xFC, "prop">>, value: "globalprop"}]
      assert psbt.global.unknown == [%{key: <<0x77, "unk">>, value: "globalunknown"}]
    end

    test "parses input por_commitment and hash preimage fields", %{psbt: psbt} do
      input = hd(psbt.inputs)
      hash20 = :binary.copy(<<0xCD>>, 20)
      hash32 = :binary.copy(<<0xAB>>, 32)

      assert input.por_commitment == "por-commitment-message"
      assert input.ripemd160 == [%{hash: hash20, preimage: "ripemd-preimage"}]
      assert input.sha256 == [%{hash: hash32, preimage: "sha256-preimage"}]
      assert input.hash160 == [%{hash: hash20, preimage: "hash160-preimage"}]
      assert input.hash256 == [%{hash: hash32, preimage: "hash256-preimage"}]
    end

    test "parses input and output proprietary and unknown records", %{psbt: psbt} do
      input = hd(psbt.inputs)
      output = hd(psbt.outputs)

      assert input.proprietary == [%{key: <<0xFC, "ip">>, value: "inputprop"}]
      assert input.unknown == [%{key: <<0x99, "iu">>, value: "inputunknown"}]
      assert output.proprietary == [%{key: <<0xFC, "op">>, value: "outputprop"}]
      assert output.unknown == [%{key: <<0x88, "ou">>, value: "outputunknown"}]
    end
  end

  # The expected result of the BIP-174 Combiner worked example: every input
  # carries TWO partial_sig records (one per signer). Guards the repeatability
  # of partial_sig — a singleton representation keeps only the last record.
  @two_partial_sigs_vector "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"

  describe "repeatable partial_sig" do
    test "an input with two partial_sig records keeps both and round-trips" do
      assert {:ok, psbt} = PSBT.decode(@two_partial_sigs_vector)

      for input <- psbt.inputs do
        assert length(input.partial_sig) == 2
      end

      assert PSBT.encode_b64(psbt) == @two_partial_sigs_vector
    end
  end

  # Builds a minimal one-input/one-output PSBT binary around the unsigned tx
  # of @new_fields_vector, with `records` spliced into the given map.
  defp psbt_with_records(records, location) do
    {:ok, psbt} = PSBT.decode(@new_fields_vector)
    tx_bytes = Bitcoinex.Transaction.Utils.serialize(psbt.global.unsigned_tx)

    tx_record =
      <<0x01, 0x00>> <>
        Bitcoinex.Transaction.Utils.serialize_compact_size_unsigned_int(byte_size(tx_bytes)) <>
        tx_bytes

    {global_records, input_records, output_records} =
      case location do
        :global -> {records, <<>>, <<>>}
        :input -> {<<>>, records, <<>>}
        :output -> {<<>>, <<>>, records}
      end

    binary =
      <<0x70736274::big-size(32), 0xFF>> <>
        tx_record <>
        global_records <> <<0x00>> <> input_records <> <<0x00>> <> output_records <> <<0x00>>

    Base.encode64(binary)
  end

  defp record(key, value) do
    <<byte_size(key)>> <> key <> <<byte_size(value)>> <> value
  end

  describe "malformed and unsupported inputs" do
    test "truncated PSBTs are rejected" do
      {:ok, valid_bytes} = Base.decode64(hd(@bip174_valid_vectors))
      truncated = binary_part(valid_bytes, 0, byte_size(valid_bytes) - 5)
      assert {:error, _reason} = PSBT.decode(Base.encode64(truncated))
    end

    test "65-byte (uncompressed) pubkeys are rejected with a distinct reason" do
      uncompressed = <<0x04>> <> :binary.copy(<<0xAB>>, 64)
      signature = :binary.copy(<<0x30>>, 8)
      origin = <<0, 0, 0, 0>>

      partial_sig = record(<<0x02>> <> uncompressed, signature)
      in_bip32 = record(<<0x06>> <> uncompressed, origin)
      out_bip32 = record(<<0x02>> <> uncompressed, origin)

      assert {:error, :uncompressed_public_key} =
               PSBT.decode(psbt_with_records(partial_sig, :input))

      assert {:error, :uncompressed_public_key} =
               PSBT.decode(psbt_with_records(in_bip32, :input))

      assert {:error, :uncompressed_public_key} =
               PSBT.decode(psbt_with_records(out_bip32, :output))
    end

    test "sighash_type is stored and re-emitted as 4 little-endian bytes" do
      psbt_b64 = psbt_with_records(record(<<0x03>>, <<0x01, 0x00, 0x00, 0x00>>), :input)
      assert {:ok, psbt} = PSBT.decode(psbt_b64)
      assert hd(psbt.inputs).sighash_type == <<0x01, 0x00, 0x00, 0x00>>
      assert PSBT.encode_b64(psbt) == psbt_b64
    end

    test "a sighash_type value that is not 4 bytes is rejected" do
      psbt_b64 = psbt_with_records(record(<<0x03>>, <<0x01>>), :input)
      assert {:error, :invalid_sighash_type} = PSBT.decode(psbt_b64)
    end

    test "a global version value that is not 4 bytes is rejected" do
      psbt_b64 = psbt_with_records(record(<<0xFB>>, <<0x02, 0x00>>), :global)
      assert {:error, :invalid_version} = PSBT.decode(psbt_b64)
    end
  end

  # BIP-174 defines each value's encoding exactly; bytes beyond it are
  # malformed. Accepting them would also break losslessness: the parsers drop
  # them, so decode |> encode_b64 would silently emit a different PSBT.
  describe "trailing bytes inside a value payload" do
    test "witness_utxo with bytes after the scriptPubKey is rejected" do
      # value = 8-byte amount, scriptPubKey [len=1, OP_TRUE], 2 junk bytes
      value = <<1000::little-size(64), 0x01, 0x51, 0xDE, 0xAD>>
      psbt_b64 = psbt_with_records(record(<<0x01>>, value), :input)
      assert {:error, :invalid_witness_utxo} = PSBT.decode(psbt_b64)
    end

    test "final_scriptwitness with bytes after the stack is rejected" do
      # value = 1 stack item [len=1, OP_TRUE], 1 junk byte
      value = <<0x01, 0x01, 0x51, 0xBB>>
      psbt_b64 = psbt_with_records(record(<<0x08>>, value), :input)
      assert {:error, :invalid_final_scriptwitness} = PSBT.decode(psbt_b64)

      # empty stack followed by a junk byte
      psbt_b64 = psbt_with_records(record(<<0x08>>, <<0x00, 0xFF>>), :input)
      assert {:error, :invalid_final_scriptwitness} = PSBT.decode(psbt_b64)
    end

    test "derivation values with a trailing partial index are rejected" do
      pubkey = <<0x02>> <> :binary.copy(<<0xAB>>, 32)
      xpub = :binary.copy(<<0x01>>, 78)
      # fingerprint + one full index + one stray byte (length ≢ 0 mod 4)
      value = <<0, 0, 0, 0>> <> <<84::little-size(32)>> <> <<0xAA>>

      assert {:error, :invalid_derivation} =
               PSBT.decode(psbt_with_records(record(<<0x01>> <> xpub, value), :global))

      assert {:error, :invalid_derivation} =
               PSBT.decode(psbt_with_records(record(<<0x06>> <> pubkey, value), :input))

      assert {:error, :invalid_derivation} =
               PSBT.decode(psbt_with_records(record(<<0x02>> <> pubkey, value), :output))
    end
  end

  # BIP-174 requires compact size uints to be minimally encoded. Accepting a
  # non-minimal length silently breaks losslessness (it re-serializes shorter),
  # and a non-minimally encoded zero key length is outright dangerous: it
  # yields an empty key that re-serializes as a map separator, so
  # decode |> encode_b64 would emit a *different valid PSBT*.
  describe "non-canonical compact size encodings" do
    test "a non-minimal key length is rejected" do
      # key length 1 encoded as <<0xFD, 0x01, 0x00>>, unknown key type 0xF0
      evil = <<0xFD, 0x01, 0x00, 0xF0, 0x01, 0xAA>>

      for location <- [:global, :input, :output] do
        assert {:error, :non_canonical_compact_size} =
                 PSBT.decode(psbt_with_records(evil, location))
      end
    end

    test "a non-minimally encoded zero key length is rejected, not read as an empty key" do
      # key length 0 encoded as <<0xFD, 0x00, 0x00>>: an empty key would
      # re-serialize as the 0x00 map separator, corrupting the PSBT on re-encode
      evil = <<0xFD, 0x00, 0x00, 0x01, 0xAA>>

      for location <- [:global, :input, :output] do
        assert {:error, :non_canonical_compact_size} =
                 PSBT.decode(psbt_with_records(evil, location))
      end
    end

    test "a non-minimal value length is rejected" do
      # unknown key type 0xF0, value length 2 encoded as <<0xFD, 0x02, 0x00>>
      evil = <<0x01, 0xF0, 0xFD, 0x02, 0x00, 0xAB, 0xCD>>

      for location <- [:global, :input, :output] do
        assert {:error, :invalid_psbt} = PSBT.decode(psbt_with_records(evil, location))
      end
    end

    test "a non-minimal global unsigned-tx value length is rejected" do
      {:ok, psbt} = PSBT.decode(@new_fields_vector)
      tx_bytes = Bitcoinex.Transaction.Utils.serialize(psbt.global.unsigned_tx)

      # the mandatory global record, with its value length inflated from one
      # byte to the non-minimal <<0xFD, len::little-16>>
      tx_record = <<0x01, 0x00, 0xFD, byte_size(tx_bytes)::little-size(16)>> <> tx_bytes
      binary = <<0x70736274::big-size(32), 0xFF>> <> tx_record <> <<0x00, 0x00, 0x00>>

      assert {:error, :non_canonical_compact_size} = PSBT.decode(Base.encode64(binary))
    end

    test "a witness_utxo with a non-minimal scriptPubKey length is rejected" do
      # 8-byte amount, scriptPubKey length 1 encoded as <<0xFD, 0x01, 0x00>>, OP_TRUE
      value = <<1000::little-size(64), 0xFD, 0x01, 0x00, 0x51>>
      psbt_b64 = psbt_with_records(record(<<0x01>>, value), :input)
      assert {:error, :invalid_witness_utxo} = PSBT.decode(psbt_b64)
    end

    test "a final_scriptwitness with a non-minimal stack count or item length is rejected" do
      # stack count 1 encoded as <<0xFD, 0x01, 0x00>>
      value = <<0xFD, 0x01, 0x00, 0x01, 0x51>>
      psbt_b64 = psbt_with_records(record(<<0x08>>, value), :input)
      assert {:error, :invalid_final_scriptwitness} = PSBT.decode(psbt_b64)

      # stack item length 1 encoded as <<0xFD, 0x01, 0x00>>
      value = <<0x01, 0xFD, 0x01, 0x00, 0x51>>
      psbt_b64 = psbt_with_records(record(<<0x08>>, value), :input)
      assert {:error, :invalid_final_scriptwitness} = PSBT.decode(psbt_b64)
    end

    test "a non_witness_utxo that does not re-serialize identically is rejected" do
      {:ok, psbt} = PSBT.decode(@new_fields_vector)
      tx_bytes = Bitcoinex.Transaction.Utils.serialize(psbt.global.unsigned_tx)

      # inflate input 0's empty scriptSig length (after version, input count,
      # txid, and vout) from 0x00 to the non-minimal <<0xFD, 0x00, 0x00>>: the
      # tx still decodes, but re-serializes minimally — losslessness is broken
      <<head::binary-size(41), 0x00, rest::binary>> = tx_bytes
      tampered = head <> <<0xFD, 0x00, 0x00>> <> rest

      psbt_b64 = psbt_with_records(record(<<0x00>>, tampered), :input)
      assert {:error, :invalid_non_witness_utxo} = PSBT.decode(psbt_b64)
    end
  end

  describe "duplicate keys in the global and output maps" do
    test "a repeated global key is rejected with :duplicate_key" do
      records = record(<<0xFB>>, <<2, 0, 0, 0>>) <> record(<<0xFB>>, <<2, 0, 0, 0>>)
      assert {:error, :duplicate_key} = PSBT.decode(psbt_with_records(records, :global))
    end

    test "a repeated output key is rejected with :duplicate_key" do
      pubkey = <<0x02>> <> :binary.copy(<<0xAB>>, 32)
      bip32 = record(<<0x02>> <> pubkey, <<0, 0, 0, 0>>)
      assert {:error, :duplicate_key} = PSBT.decode(psbt_with_records(bip32 <> bip32, :output))
    end
  end

  describe "unknown record round-trip property" do
    test "any set of unknown input records survives decode |> encode_b64 byte-for-byte" do
      # Key type bytes outside every known input type (0x00-0x0d) and the
      # proprietary prefix (0xFC), so each record lands in :unknown.
      key_gen =
        gen all(
              type <- StreamData.integer(0x20..0xF0),
              suffix <- StreamData.binary(max_length: 40)
            ) do
          <<type>> <> suffix
        end

      check all(
              keys <- StreamData.uniq_list_of(key_gen, min_length: 1, max_length: 5),
              values <-
                StreamData.list_of(StreamData.binary(max_length: 60), length: length(keys))
            ) do
        records = Enum.zip(keys, values) |> Enum.map_join(fn {k, v} -> record(k, v) end)
        psbt_b64 = psbt_with_records(records, :input)

        assert {:ok, psbt} = PSBT.decode(psbt_b64)
        assert PSBT.encode_b64(psbt) == psbt_b64
      end
    end
  end

  describe "encoding a PSBT without an unsigned tx" do
    test "encode_b64/1 and to_file/2 return an error instead of emitting an invalid PSBT" do
      psbt = %PSBT{global: %Global{}, inputs: [], outputs: []}
      assert {:error, :missing_unsigned_tx} = PSBT.encode_b64(psbt)
      assert {:error, :missing_unsigned_tx} = PSBT.to_file(psbt, "./test/never-written.psbt")
      refute File.exists?("./test/never-written.psbt")
    end
  end
end
