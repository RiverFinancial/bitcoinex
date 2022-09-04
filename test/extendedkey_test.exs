defmodule Bitcoinex.Secp256k1.ExtendedKeyTest do
  use ExUnit.Case
  doctest Bitcoinex.ExtendedKey

  alias Bitcoinex.ExtendedKey

  @min_hardened_child_num 0x80000000
  # 2^32
  @max_hardened_child_num 0x100000000

  @invalid_xkeys [
    # changed prefix
    "zpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    # invalid char
    "xpubi61MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    # invalid prefix
    "apub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    # invalid len
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet",
    # invalid len
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1E",
    # invalid len (with valid checksum)
    "Deb7pNXSbX7qSvc2eMjkNYTrggh4pBgYa2QMFjEjj6hUy1iHp71d1gf3ue7Ni7X8Pkhcy13aakoEYSMS1DFiMaXB4qYhN33dh3oqD9n1YWSxVk"
  ]

  @bip32_test_case_1 %{
    # test vectors from bip32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    seed: "000102030405060708090a0b0c0d0e0f",
    xpub_m:
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    xpub_m_obj: %Bitcoinex.ExtendedKey{
      chaincode:
        <<135, 61, 255, 129, 192, 47, 82, 86, 35, 253, 31, 229, 22, 126, 172, 58, 85, 160, 73,
          222, 61, 49, 75, 180, 46, 226, 39, 255, 237, 55, 213, 8>>,
      checksum: <<171, 71, 59, 33>>,
      child_num: <<0, 0, 0, 0>>,
      depth: <<0>>,
      key:
        <<3, 57, 163, 96, 19, 48, 21, 151, 218, 239, 65, 251, 229, 147, 160, 44, 197, 19, 208,
          181, 85, 39, 236, 45, 241, 5, 14, 46, 143, 244, 156, 133, 194>>,
      parent_fingerprint: <<0, 0, 0, 0>>,
      prefix: <<4, 136, 178, 30>>
    },
    xprv_m:
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
    xprv_m_obj: %Bitcoinex.ExtendedKey{
      chaincode:
        <<135, 61, 255, 129, 192, 47, 82, 86, 35, 253, 31, 229, 22, 126, 172, 58, 85, 160, 73,
          222, 61, 49, 75, 180, 46, 226, 39, 255, 237, 55, 213, 8>>,
      checksum: <<231, 126, 157, 113>>,
      child_num: <<0, 0, 0, 0>>,
      depth: <<0>>,
      key:
        <<0, 232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197, 178, 20,
          49, 56, 23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53>>,
      parent_fingerprint: <<0, 0, 0, 0>>,
      prefix: <<4, 136, 173, 228>>
    },
    xpub_m_0h:
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    xprv_m_0h:
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    xpub_m_0h_1:
      "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    xprv_m_0h_1:
      "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
    xpub_m_0h_1_2h:
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
    xprv_m_0h_1_2h:
      "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
    xpub_m_0h_1_2h_2:
      "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
    xprv_m_0h_1_2h_2:
      "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
    xpub_m_0h_1_2h_2_1000000000:
      "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
    xprv_m_0h_1_2h_2_1000000000:
      "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
  }

  @bip32_test_case_2 %{
    seed:
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    xpub_m:
      "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
    xprv_m:
      "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
    xpub_m_0:
      "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
    xprv_m_0:
      "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
    xpub_m_0_2147483647h:
      "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
    xprv_m_0_2147483647h:
      "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
    xpub_m_0_2147483647h_1:
      "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
    xprv_m_0_2147483647h_1:
      "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
    xpub_m_0_2147483647h_1_2147483646h:
      "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
    xprv_m_0_2147483647h_1_2147483646h:
      "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
    xpub_m_0_2147483647h_1_2147483646h_2:
      "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
    xprv_m_0_2147483647h_1_2147483646h_2:
      "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
  }

  @bip32_test_case_3 %{
    # Test for retention of leading Zeros
    seed:
      "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
    xpub_m:
      "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
    xprv_m:
      "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
    xpub_m_0h:
      "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
    xprv_m_0h:
      "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
  }

  @bip49_test_case %{
    masterseedWords:
      ~w(abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about),
    # (testnet)
    masterseed:
      "uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd",

    # Account 0, root: m/49'/1'/0'
    # (testnet)
    account0Xpriv:
      "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n",
    # (testnet)
    account0Xpub:
      "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY",

    # Account 0, first receiving private key: m/49'/1'/0'/0/0
    account0recvPrivateKey: "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ",
    account0recvPrivateKeyHex: "c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8",
    account0recvPublicKeyHex:
      "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f",

    # Address derivation
    keyhash: "38971f73930f6c141d977ac4fd4a727c854935b3",
    scriptSig: "001438971f73930f6c141d977ac4fd4a727c854935b3",
    addressBytes: "336caa13e08b96080a32b5d818d59b4ab3b36742",

    # addressBytes base58check encoded for testnet
    # (testnet)
    address: "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"
  }

  @bip84_test_case %{
    # test case from BIP 84: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors
    # mnemonic: ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
    c_rootpriv:
      "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5",
    c_rootpriv_obj: %ExtendedKey{
      chaincode:
        <<121, 35, 64, 141, 173, 211, 199, 181, 110, 237, 21, 86, 119, 7, 174, 94, 93, 202, 8,
          157, 233, 114, 224, 127, 59, 134, 4, 80, 226, 163, 183, 14>>,
      child_num: <<0, 0, 0, 0>>,
      depth: <<0>>,
      key:
        <<0, 24, 55, 193, 190, 142, 41, 149, 236, 17, 205, 162, 176, 102, 21, 27, 226, 207, 180,
          138, 223, 158, 71, 177, 81, 212, 106, 218, 179, 162, 28, 223, 103>>,
      parent_fingerprint: <<0, 0, 0, 0>>,
      prefix: <<4, 178, 67, 12>>
    },
    c_rootpub:
      "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF",
    c_rootpub_obj: %ExtendedKey{
      chaincode:
        <<121, 35, 64, 141, 173, 211, 199, 181, 110, 237, 21, 86, 119, 7, 174, 94, 93, 202, 8,
          157, 233, 114, 224, 127, 59, 134, 4, 80, 226, 163, 183, 14>>,
      child_num: <<0, 0, 0, 0>>,
      depth: <<0>>,
      key:
        <<3, 217, 2, 243, 95, 86, 14, 4, 112, 198, 51, 19, 199, 54, 145, 104, 217, 215, 223, 45,
          73, 191, 41, 95, 217, 251, 124, 177, 9, 204, 238, 4, 148>>,
      parent_fingerprint: <<0, 0, 0, 0>>,
      prefix: <<4, 178, 71, 70>>
    },
    # Account 0, root: m/84'/0'/0'
    c_xpriv:
      "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
    c_xpub:
      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    # Account 0, first receiving address: m/84'/0'/0'/0/0
    c_privkey: "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
    c_pubkey: "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
    c_address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
  }

  @derivation_paths_to_strings [
    %{
      str: "84/0/0/2/1/",
      deriv: %ExtendedKey.DerivationPath{child_nums: [84, 0, 0, 2, 1]}
    },
    %{
      str: "84'/0'/",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    },
    %{
      str: "84'/0'/",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    },
    %{
      str: "84'/0'/1/2/2147483647/",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [
          84 + @min_hardened_child_num,
          0 + @min_hardened_child_num,
          1,
          2,
          2_147_483_647
        ]
      }
    }
  ]

  @strings_to_derivation_paths [
    %{
      str: "84/0/0/2/1/",
      deriv: %ExtendedKey.DerivationPath{child_nums: [84, 0, 0, 2, 1]}
    },
    %{
      str: "m/84'/0'/0'/2/1",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [
          84 + @min_hardened_child_num,
          0 + @min_hardened_child_num,
          2_147_483_648,
          2,
          1
        ]
      }
    },
    %{
      str: "m/84'/0'/",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    },
    %{
      str: "m/84'/0'",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    },
    %{
      str: "84'/0'",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    },
    %{
      str: "84'/0'/",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    },
    %{
      str: "84'/0'/1/2/2147483647",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [
          84 + @min_hardened_child_num,
          0 + @min_hardened_child_num,
          1,
          2,
          2_147_483_647
        ]
      }
    },
    %{
      str: "m/84h/0h/0h/2/1",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [
          84 + @min_hardened_child_num,
          0 + @min_hardened_child_num,
          2_147_483_648,
          2,
          1
        ]
      }
    },
    %{
      str: "m/84h/0h/",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    },
    %{
      str: "84h/0h",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    },
    %{
      str: "84h/0h/",
      deriv: %ExtendedKey.DerivationPath{
        child_nums: [84 + @min_hardened_child_num, 0 + @min_hardened_child_num]
      }
    }
  ]

  @error_derivation_path_strings [
    "a/82/1",
    "m/85//1/",
    "h/5/",
    "0/0/h",
    "h",
    "'",
    "0/h/0",
    "m/1/1/#{@max_hardened_child_num}",
    "m/-1/0/1"
  ]

  @switch_prefixes_examples [
    %{
      xprv: "xprv9s21ZrQH143K2WGtpJzs2er7Gmf14DG7LAGUYqu258PZSnJoBCn1ji9LA98z9qgMb3RGgrVjmCrS5qQVJNsLfKB7j7cF3gLoqnNqhQgTSe1",
      yprv: "yprvABrGsX5C9jansoU1efnVEjwcSjoSzqFcFGnhLEnuT8mSVt82RrwaMmoUBM6a9kLGzgY5SL6JDsCyy82425HMTYribTJfdbAJ7WSV5xJadR1",
      zprv: "zprvAWgYBBk7JR8Gj6f8V2a7Sq37chwtwTF7APJv7dgnq99KYywFgX78yqTcCZ4A9ezCQKetBogrgXZXrQdcjmhNFnYKTo16DVynPEW8UYJW24M",
    },
    %{
      xprv: "xprv9s21ZrQH143K2rjUSB7cHKRPQbKawzWnY8WpijEume6RsZj1YHnstedsehZr3PpzEXctHMeYt8XmfPPSF24ZHQteAhC4djGU92j1r3Jgp3L",
      yprv: "yprvABrGsX5C9jant9vbGXuEVQWtaZU2tcWHTF33W88o9eUJvfYEnwxSWiJ1fuXS3JUueAjh2qF7LntKYfzzxiUa5eaF32tVDe5xQknfEcsqyG7",
      zprv: "zprvAWgYBBk7JR8GjT7i6tgrhVcPkXcUqEVnNMZGHX2gXerBymMU3c818mx9h7V23D8q3orVnJqfoTEsRxcZgQtastFquNauoYuSgUrJd6S8Ex9",
    }
  ]

  # Extended Key Testing

  describe "parse_extended_key/1" do
    test "successfully parse extended xprv" do
      t = @bip32_test_case_1
      # priv
      assert ExtendedKey.parse_extended_key(t.xprv_m) == {:ok, t.xprv_m_obj}
      assert ExtendedKey.display_extended_key(t.xprv_m_obj) == t.xprv_m
      # pub
      assert ExtendedKey.parse_extended_key(t.xpub_m) == {:ok, t.xpub_m_obj}
      assert ExtendedKey.display_extended_key(t.xpub_m_obj) == t.xpub_m
    end
  end

  describe "to_extended_public_key/1" do
    test "successfully turn zprv into zpub" do
      t = @bip84_test_case
      assert ExtendedKey.to_extended_public_key(t.c_rootpriv_obj) == t.c_rootpub_obj
    end

    test "successfully turn xprv into xpub" do
      t = @bip32_test_case_1
      assert ExtendedKey.to_extended_public_key(t.xprv_m_obj) == {:ok, t.xpub_m_obj}
    end
  end

  describe "child derivation" do
    test "fail to derive hardened children from pub parent_fingerprint" do
      t = @bip32_test_case_1

      xpub = ExtendedKey.parse_extended_key(t.xpub_m)

      assert ExtendedKey.derive_public_child(xpub, @min_hardened_child_num) ==
               {:error, "idx must be in 0..2**31-1"}

      assert ExtendedKey.derive_public_child(xpub, @min_hardened_child_num + 1) ==
               {:error, "idx must be in 0..2**31-1"}

      assert ExtendedKey.derive_public_child(xpub, @max_hardened_child_num - 1) ==
               {:error, "idx must be in 0..2**31-1"}
    end

    test "fail to derive children with invalid index" do
      t = @bip32_test_case_1

      xprv = ExtendedKey.parse_extended_key(t.xprv_m)
      xpub = ExtendedKey.parse_extended_key(t.xpub_m)

      assert ExtendedKey.derive_private_child(xprv, @max_hardened_child_num) ==
               {:error, "idx must be in 0..2**32-1"}

      assert ExtendedKey.derive_private_child(xprv, @max_hardened_child_num + 1) ==
               {:error, "idx must be in 0..2**32-1"}

      assert ExtendedKey.derive_private_child(xprv, -1) == {:error, "idx must be in 0..2**32-1"}

      assert ExtendedKey.derive_public_child(xpub, -1) == {:error, "idx must be in 0..2**31-1"}
    end
  end

  describe "BIP84 tests" do
    test "successfully derive zprv child key at path m/84'/0'/0'/" do
      t = @bip84_test_case

      child_key =
        t.c_rootpriv_obj
        |> ExtendedKey.derive_private_child(@min_hardened_child_num + 84)
        |> ExtendedKey.derive_private_child(@min_hardened_child_num)
        |> ExtendedKey.derive_private_child(@min_hardened_child_num)

      assert ExtendedKey.display_extended_key(child_key) == t.c_xpriv
    end

    test "successfully derive zpub child key at path m/84'/0'/0'/" do
      t = @bip84_test_case

      child_key =
        t.c_rootpriv_obj
        |> ExtendedKey.derive_private_child(@min_hardened_child_num + 84)
        |> ExtendedKey.derive_private_child(@min_hardened_child_num)
        |> ExtendedKey.derive_public_child(@min_hardened_child_num)

      assert ExtendedKey.display_extended_key(child_key) == t.c_xpub
    end

    test "successfully derive private key WIF at m/84'/0'/0'/0/0" do
      t = @bip84_test_case

      child_key =
        t.c_rootpriv_obj
        |> ExtendedKey.derive_private_child(@min_hardened_child_num + 84)
        |> ExtendedKey.derive_private_child(@min_hardened_child_num)
        |> ExtendedKey.derive_private_child(@min_hardened_child_num)
        |> ExtendedKey.derive_private_child(0)
        |> ExtendedKey.derive_private_child(0)
        |> ExtendedKey.to_private_key()

      assert Bitcoinex.Secp256k1.PrivateKey.wif!(child_key, :mainnet) == t.c_privkey
    end

    test "successfully derive account xpub and then public key at m/84'/0'/0'/0/0" do
      t = @bip84_test_case

      child_key =
        t.c_rootpriv_obj
        |> ExtendedKey.derive_private_child(@min_hardened_child_num + 84)
        |> ExtendedKey.derive_private_child(@min_hardened_child_num)
        |> ExtendedKey.derive_public_child(@min_hardened_child_num)
        |> ExtendedKey.derive_public_child(0)
        |> ExtendedKey.derive_public_child(0)
        |> ExtendedKey.to_public_key()

      assert Bitcoinex.Secp256k1.Point.serialize_public_key(child_key) == t.c_pubkey
    end
  end

  describe "BIP49 tests" do
    test "successfully derive private keys from account yprv" do
      t = @bip49_test_case

      prvkey =
        t.account0Xpriv
        |> ExtendedKey.parse_extended_key()
        |> ExtendedKey.derive_private_child(0)
        |> ExtendedKey.derive_private_child(0)
        |> ExtendedKey.to_private_key()

      assert Bitcoinex.Secp256k1.PrivateKey.wif!(prvkey, :testnet) == t.account0recvPrivateKey
    end

    test "successfully derive public key from account ypub  " do
      t = @bip49_test_case

      pubkey =
        t.account0Xpub
        |> ExtendedKey.parse_extended_key()
        |> ExtendedKey.derive_public_child(0)
        |> ExtendedKey.derive_public_child(0)
        |> ExtendedKey.to_public_key()

      assert Bitcoinex.Secp256k1.Point.serialize_public_key(pubkey) == t.account0recvPublicKeyHex

  end

  describe "BIP32 tests" do
    # Test 1
    test "BIP32 tests 1: successfully convert xprv to xpub." do
      t = @bip32_test_case_1

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0h)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0h)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0h_1)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0h_1)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0h_1_2h)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0h_1_2h_2)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h_2)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0h_1_2h_2_1000000000)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h_2_1000000000)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}
    end

    test "BIP32 tests 1: derive prv keys in sequence" do
      t = @bip32_test_case_1
      # derive prv child from prv parent_fingerprint
      {:ok, m_xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, m_0h_xprv} = ExtendedKey.derive_private_child(m_xprv, @min_hardened_child_num)

      assert ExtendedKey.parse_extended_key(t.xprv_m_0h) == {:ok, m_0h_xprv}

      # derive child m/0'/1
      {:ok, m_0h_1_xprv} = ExtendedKey.derive_private_child(m_0h_xprv, 1)
      assert ExtendedKey.parse_extended_key(t.xprv_m_0h_1) == {:ok, m_0h_1_xprv}
    end

    test "BIP32 tests 1: derive pub keys from master prv key" do
      t = @bip32_test_case_1

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, m_0h_xpub} = ExtendedKey.derive_public_child(xprv, @min_hardened_child_num)

      assert ExtendedKey.parse_extended_key(t.xpub_m_0h) == {:ok, m_0h_xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xprv} = ExtendedKey.derive_private_child(xprv, @min_hardened_child_num)
      {:ok, xprv} = ExtendedKey.derive_private_child(xprv, 1)
      {:ok, m_0h_1_2h_xpub} = ExtendedKey.derive_public_child(xprv, @min_hardened_child_num + 2)

      assert ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h) == {:ok, m_0h_1_2h_xpub}
    end

    test "BIP32 tests 1: derive m/0'/1/2'/2/1000000000 from master key" do
      t = @bip32_test_case_1

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xprv} = ExtendedKey.derive_private_child(xprv, @min_hardened_child_num)
      {:ok, xprv} = ExtendedKey.derive_private_child(xprv, 1)
      {:ok, xprv} = ExtendedKey.derive_private_child(xprv, @min_hardened_child_num + 2)
      {:ok, xprv} = ExtendedKey.derive_private_child(xprv, 2)
      {:ok, m_0h_1_2h_2_1000000000_xprv} = ExtendedKey.derive_private_child(xprv, 1_000_000_000)

      assert ExtendedKey.parse_extended_key(t.xprv_m_0h_1_2h_2_1000000000) ==
               {:ok, m_0h_1_2h_2_1000000000_xprv}
    end

    test "BIP32 tests 1: derive pub child from pub parent_fingerprint" do
      t = @bip32_test_case_1

      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0h)
      {:ok, m_0h_1_xpub} = ExtendedKey.derive_public_child(xpub, 1)

      assert ExtendedKey.parse_extended_key(t.xpub_m_0h_1) == {:ok, m_0h_1_xpub}

      {:ok, xpub_m_0h_1_2h} = ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h)
      {:ok, m_0h_1_2h_2_xpub} = ExtendedKey.derive_public_child(xpub_m_0h_1_2h, 2)

      assert ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h_2) == {:ok, m_0h_1_2h_2_xpub}

      {:ok, m_0h_1_2h_2_1000000000_xpub} =
        m_0h_1_2h_2_xpub
        |> ExtendedKey.derive_public_child(1_000_000_000)

      assert ExtendedKey.parse_extended_key(t.xpub_m_0h_1_2h_2_1000000000) ==
               {:ok, m_0h_1_2h_2_1000000000_xpub}
    end

    test "BIP32 tests 1: to_public_key works for both xprv and xpubs" do
      t = @bip32_test_case_1

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m)

      pub = ExtendedKey.to_public_key(xpub)
      # test that to_public_key works for xprv and xpub keys
      assert ExtendedKey.to_public_key(xprv) == pub
    end

    test "BIP32 tests 1: seed to master prv key" do
      t = @bip32_test_case_1

      seed = t.seed |> Base.decode16!(case: :lower)
      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)

      assert ExtendedKey.seed_to_master_private_key(seed) == {:ok, xprv}
    end

    test "BIP32 tests 1: derive key from seed and deriv path" do
      t = @bip32_test_case_1

      seed = t.seed |> Base.decode16!(case: :lower)
      {:ok, xprv} = t.xprv_m |> ExtendedKey.parse_extended_key()
      deriv = %ExtendedKey.DerivationPath{child_nums: []}

      assert ExtendedKey.derive_extended_key(seed, deriv) == {:ok, xprv}

      # derive m/0'/1
      {:ok, xprv} = t.xprv_m_0h_1 |> ExtendedKey.parse_extended_key()
      deriv = %ExtendedKey.DerivationPath{child_nums: [@min_hardened_child_num, 1]}

      assert ExtendedKey.derive_extended_key(seed, deriv) == {:ok, xprv}

      # derive xprv_m_0h_1_2h_2_1000000000
      {:ok, xprv_m_0h_1_2h_2_1000000000} =
        t.xprv_m_0h_1_2h_2_1000000000 |> ExtendedKey.parse_extended_key()

      deriv = %ExtendedKey.DerivationPath{
        child_nums: [@min_hardened_child_num, 1, @min_hardened_child_num + 2, 2, 1_000_000_000]
      }

      assert ExtendedKey.derive_extended_key(seed, deriv) == {:ok, xprv_m_0h_1_2h_2_1000000000}
    end

    # Test 2

    test "BIP32 tests 2: successfully convert xprv to xpub." do
      t = @bip32_test_case_2

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0_2147483647h)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0_2147483647h)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0_2147483647h_1)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0_2147483647h_1)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0_2147483647h_1_2147483646h)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0_2147483647h_1_2147483646h)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0_2147483647h_1_2147483646h_2)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0_2147483647h_1_2147483646h_2)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}
    end

    test "BIP32 tests 2: derive prv keys in sequence" do
      t = @bip32_test_case_2
      # derive prv child from prv parent_fingerprint
      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, m_0_xprv} = ExtendedKey.derive_private_child(xprv, 0)

      assert ExtendedKey.parse_extended_key(t.xprv_m_0) == {:ok, m_0_xprv}

      # derive child m/0/2147483647h
      {:ok, m_0_2147483647h_xprv} =
        ExtendedKey.derive_private_child(m_0_xprv, 2_147_483_647 + @min_hardened_child_num)

      assert ExtendedKey.parse_extended_key(t.xprv_m_0_2147483647h) == {:ok, m_0_2147483647h_xprv}
    end

    test "BIP32 tests 2: derive pub keys from master prv key" do
      t = @bip32_test_case_2

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, m_0_xpub} = ExtendedKey.derive_public_child(xprv, 0)

      assert ExtendedKey.parse_extended_key(t.xpub_m_0) == {:ok, m_0_xpub}

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xprv_temp} = ExtendedKey.derive_private_child(xprv, 0)

      {:ok, xprv_temp} =
        ExtendedKey.derive_private_child(xprv_temp, 2_147_483_647 + @min_hardened_child_num)

      {:ok, m_0_2147483647h_1_xpub} = ExtendedKey.derive_public_child(xprv_temp, 1)

      assert ExtendedKey.parse_extended_key(t.xpub_m_0_2147483647h_1) ==
               {:ok, m_0_2147483647h_1_xpub}
    end

    test "BIP32 tests 2: derive child pub keys from prv and pubkey" do
      t = @bip32_test_case_2

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xpub1} = ExtendedKey.derive_public_child(xprv, 0)

      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m)
      {:ok, xpub2} = ExtendedKey.derive_public_child(xpub, 0)

      assert xpub1 == xpub2

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0_2147483647h)
      {:ok, xpub1} = ExtendedKey.derive_public_child(xprv, 1)

      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0_2147483647h)
      {:ok, xpub2} = ExtendedKey.derive_public_child(xpub, 1)

      assert xpub1 == xpub2
    end

    test "BIP32 tests 2: seed to master prv key" do
      t = @bip32_test_case_2

      seed = t.seed |> Base.decode16!(case: :lower)
      {:ok, xprv} = t.xprv_m |> ExtendedKey.parse_extended_key()

      assert ExtendedKey.seed_to_master_private_key(seed) == {:ok, xprv}
    end

    test "BIP32 tests 2: derive key from seed and deriv path" do
      t = @bip32_test_case_2

      seed = t.seed |> Base.decode16!(case: :lower)
      {:ok, xprv} = t.xprv_m |> ExtendedKey.parse_extended_key()
      deriv = %ExtendedKey.DerivationPath{child_nums: []}

      assert ExtendedKey.derive_extended_key(seed, deriv) == {:ok, xprv}

      {:ok, xprv} = t.xprv_m_0_2147483647h |> ExtendedKey.parse_extended_key()

      deriv = %ExtendedKey.DerivationPath{
        child_nums: [0, 2_147_483_647 + @min_hardened_child_num]
      }

      assert ExtendedKey.derive_extended_key(seed, deriv) == {:ok, xprv}

      {:ok, xprv_m_0_2147483647h_1_2147483646h_2} =
        t.xprv_m_0_2147483647h_1_2147483646h_2 |> ExtendedKey.parse_extended_key()

      deriv = %ExtendedKey.DerivationPath{
        child_nums: [
          0,
          2_147_483_647 + @min_hardened_child_num,
          1,
          2_147_483_646 + @min_hardened_child_num,
          2
        ]
      }

      assert ExtendedKey.derive_extended_key(seed, deriv) ==
               {:ok, xprv_m_0_2147483647h_1_2147483646h_2}
    end

    # Test 3

    test "BIP32 tests 3: derive public key from private key" do
      t = @bip32_test_case_3

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}
      # check that to_extended_public_key is identity for xpub
      assert ExtendedKey.to_extended_public_key(xpub) == xpub

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m_0h)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m_0h)
      assert ExtendedKey.to_extended_public_key(xprv) == {:ok, xpub}
      assert ExtendedKey.to_extended_public_key(xpub) == xpub
    end

    test "BIP32 tests 3: derive prv child from parent" do
      t = @bip32_test_case_3

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xprv_m_0h} = ExtendedKey.derive_private_child(xprv, @min_hardened_child_num)

      assert ExtendedKey.parse_extended_key(t.xprv_m_0h) == {:ok, xprv_m_0h}
    end

    test "BIP32 tests 3: derive pub child from prv parent" do
      t = @bip32_test_case_3

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xpub_m_0h} = ExtendedKey.derive_public_child(xprv, @min_hardened_child_num)

      assert ExtendedKey.display_extended_key(xpub_m_0h) == t.xpub_m_0h
    end

    test "BIP32 tests 3: derive master prv key from seed" do
      t = @bip32_test_case_3

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)

      {:ok, s_xprv} =
        t.seed
        |> Base.decode16!(case: :lower)
        |> ExtendedKey.seed_to_master_private_key()

      assert xprv == s_xprv
    end

    test "BIP32 tests 3: derive child prv key from seed" do
      t = @bip32_test_case_3

      {:ok, xprv_m_0h} = ExtendedKey.parse_extended_key(t.xprv_m_0h)
      deriv = %ExtendedKey.DerivationPath{child_nums: [@min_hardened_child_num]}

      {:ok, s_xprv_m_0h} =
        t.seed
        |> Base.decode16!(case: :lower)
        |> ExtendedKey.derive_extended_key(deriv)

      assert xprv_m_0h == s_xprv_m_0h
    end
  end

  describe "Invalid Key testing" do
    test "invalid key testing" do
      for t <- @invalid_xkeys do
        {err, _} = ExtendedKey.parse_extended_key(t)
        assert err == :error
      end
    end
  end

  describe "Derive Private and public key, sign message, verify signature" do
    test "derive prv and public key, sign msg, verify" do
      t = @bip32_test_case_1

      {:ok, xprv} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m)

      {:ok, prv} = ExtendedKey.to_private_key(xprv)
      {:ok, pub} = ExtendedKey.to_public_key(xpub)

      msg = "eat out from 5 pounds"
      z = :binary.decode_unsigned(Bitcoinex.Utils.double_sha256(msg))
      sig = Bitcoinex.Secp256k1.PrivateKey.sign(prv, z)
      assert Bitcoinex.Secp256k1.verify_signature(pub, z, sig)
    end
  end

  describe "Switch extended key prefixes" do
    test "switch_prefix" do
      for t <- @switch_prefixes_examples do
        t_xprv = ExtendedKey.parse_extended_key(t.xprv)
        t_yprv = ExtendedKey.parse_extended_key(t.yprv)
        t_zprv = ExtendedKey.parse_extended_key(t.zprv)

        yprv = ExtendedKey.switch_prefix(t_xprv, :yprv)
        zprv = ExtendedKey.switch_prefix(t_xprv, :zprv)

        assert yprv == t_yprv
        assert zprv == t_zprv

        xprv = ExtendedKey.switch_prefix(zprv, :xprv)

        assert xprv == t_xprv
      end
    end
  end

  describe "Fail on attempt to derive hardened child from pubkey" do
    test "fail to derive hardened child from pubkey parent" do
      t = @bip32_test_case_3

      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m)
      {err, _msg} = ExtendedKey.derive_child_key(xpub, @min_hardened_child_num)
      assert :error == err
    end

    test "fail to derive hardened child from pubkey parent with deriv path" do
      t = @bip32_test_case_3

      deriv = %ExtendedKey.DerivationPath{
        child_nums: [@min_hardened_child_num, 1]
      }

      {:ok, xpub} = ExtendedKey.parse_extended_key(t.xpub_m)
      {err, _msg} = ExtendedKey.derive_extended_key(xpub, deriv)
      assert :error == err
    end
  end

  # Derivation Path Testing

  describe "derive_extended_key/2 using BIP 84 test cases" do
    test "test use of deriv path" do
      t = @bip84_test_case
      deriv = %ExtendedKey.DerivationPath{child_nums: [@min_hardened_child_num + 84, @min_hardened_child_num, @min_hardened_child_num]}

      child_key =
        t.c_rootpriv_obj
        |> ExtendedKey.derive_extended_key(deriv)

      assert ExtendedKey.display_extended_key(child_key) == t.c_xpriv
    end

    test "successfully derive zpub child key at path m/84'/0'/0'/" do
      t = @bip84_test_case
      deriv = %ExtendedKey.DerivationPath{child_nums: [@min_hardened_child_num + 84, @min_hardened_child_num, @min_hardened_child_num]}

      child_key =
        t.c_rootpriv_obj
        |> ExtendedKey.derive_extended_key(deriv)
        |> ExtendedKey.to_extended_public_key()

      assert ExtendedKey.display_extended_key(child_key) == t.c_xpub
    end

    test "successfully derive private key WIF at m/84'/0'/0'/0/0" do
      t = @bip84_test_case
      deriv = %ExtendedKey.DerivationPath{child_nums: [@min_hardened_child_num + 84, @min_hardened_child_num, @min_hardened_child_num, 0, 0]}

      child_key =
        t.c_rootpriv_obj
        |> ExtendedKey.derive_extended_key(deriv)
        |> ExtendedKey.to_private_key()

      assert Bitcoinex.Secp256k1.PrivateKey.wif!(child_key, :mainnet) == t.c_privkey
    end
  end

  describe "derive_extended_key/2 using BIP 32 test cases" do
    test "test use of deriv path" do
      t = @bip32_test_case_1

      deriv = %ExtendedKey.DerivationPath{
        child_nums: [@min_hardened_child_num, 1, @min_hardened_child_num + 2, 2]
      }

      {:ok, child_key} =
        t.xprv_m_obj
        |> ExtendedKey.derive_extended_key(deriv)

      assert ExtendedKey.display_extended_key(child_key) == t.xprv_m_0h_1_2h_2
    end

    test "successfully derive xpub child key with derivation path" do
      t = @bip32_test_case_2

      deriv = %ExtendedKey.DerivationPath{
        child_nums: [
          0,
          @min_hardened_child_num + 2_147_483_647,
          1,
          @min_hardened_child_num + 2_147_483_646
        ]
      }

      {:ok, xprv_t1} = ExtendedKey.parse_extended_key(t.xprv_m)
      {:ok, xprv_t2} = ExtendedKey.derive_extended_key(xprv_t1, deriv)
      {:ok, child_key} = ExtendedKey.to_extended_public_key(xprv_t2)

      assert ExtendedKey.display_extended_key(child_key) == t.xpub_m_0_2147483647h_1_2147483646h
    end

    test "test use of deriv path bip32 test 2" do
      t = @bip32_test_case_2
      deriv = %ExtendedKey.DerivationPath{
        child_nums: [
          0,
          2_147_483_647 + @min_hardened_child_num,
          1,
          2_147_483_646 + @min_hardened_child_num,
          2
        ]
      }

      {:ok, m} = ExtendedKey.parse_extended_key(t.xprv_m)

      {:ok, child_key} = ExtendedKey.derive_extended_key(m, deriv)

      assert ExtendedKey.parse_extended_key(t.xprv_m_0_2147483647h_1_2147483646h_2) ==
               {:ok, child_key}
    end
  end

  describe "Derivation Path parse/ser testing" do
    test "from_string/1" do
      for t <- @strings_to_derivation_paths do
        assert ExtendedKey.DerivationPath.from_string(t.str) == {:ok, t.deriv}
      end
    end

    test "to_string/1" do
      for t <- @derivation_paths_to_strings do
        assert ExtendedKey.DerivationPath.to_string(t.deriv) == {:ok, t.str}
      end
    end

    test "Raise exceptions on invalid derivation paths" do
      for t <- @error_derivation_path_strings do
        {res, _} = ExtendedKey.DerivationPath.from_string(t)
        assert :error == res
      end
    end
  end
end
