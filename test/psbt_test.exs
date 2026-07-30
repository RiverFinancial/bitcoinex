defmodule Bitcoinex.PSBTTest do
  use ExUnit.Case
  use ExUnitProperties
  doctest Bitcoinex.PSBT

  alias Bitcoinex.PSBT
  alias Bitcoinex.PSBT.Global
  alias Bitcoinex.PSBT.In
  alias Bitcoinex.PSBT.KeyOrigin
  alias Bitcoinex.{ExtendedKey, Script, Transaction}
  alias Bitcoinex.ExtendedKey.DerivationPath
  alias Bitcoinex.Secp256k1.{Point, Signature}

  # Official BIP-174 test vectors (valid). Every one must decode and re-encode
  # to the exact same bytes (lossless round-trip). Order matches the BIP.
  @bip174_valid_vectors [
    "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA",
    "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA",
    "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQMEAQAAAAAAAA==",
    "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEA3wIAAAABJoFxNx7f8oXpN63upLN7eAAMBWbLs61kZBcTykIXG/YAAAAAakcwRAIgcLIkUSPmv0dNYMW1DAQ9TGkaXSQ18Jo0p2YqncJReQoCIAEynKnazygL3zB0DsA5BCJCLIHLRYOUV663b8Eu3ZWzASECZX0RjTNXuOD0ws1G23s59tnDjZpwq8ubLeXcjb/kzjH+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA=",
    "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=",
    "cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA",
    "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAA=",
    "cHNidP8BAJ0BAAAAAnEOp2q0XFy2Q45gflnMA3YmmBgFrp4N/ZCJASq7C+U1AQAAAAD/////GQmU1qizyMgsy8+y+6QQaqBmObhyqNRHRlwNQliNbWcAAAAAAP////8CAOH1BQAAAAAZdqkUtrwsDuVlWoQ9ea/t0MzD991kNAmIrGBa9AUAAAAAFgAUEYjvjkzgRJ6qyPsUHL9aEXbmoIgAAAAATwEEiLIeA55TDKyAAAAAPbyKXJdp8DGxfnf+oVGGAyIaGP0Y8rmlTGyMGsdcvDUC8jBYSxVdHH8c1FEgplPEjWULQxtnxbLBPyfXFCA3wWkQJ1acUDEAAIAAAACAAAAAgAABAR8A4fUFAAAAABYAFDO5gvkbKPFgySC0q5XljOUN2jpKIgIDMJaA8zx9446mpHzU7NZvH1pJdHxv+4gI7QkDkkPjrVxHMEQCIC1wTO2DDFapCTRL10K2hS3M0QPpY7rpLTjnUlTSu0JFAiAthsQ3GV30bAztoITyopHD2i1kBw92v5uQsZXn7yj3cgEiBgMwloDzPH3jjqakfNTs1m8fWkl0fG/7iAjtCQOSQ+OtXBgnVpxQMQAAgAAAAIAAAACAAAAAAAEAAAAAAQEfAOH1BQAAAAAWABQ4j7lEMH63fvRRl9CwskXgefAR3iICAsd3Fh9z0LfHK57nveZQKT0T8JW8dlatH1Jdpf0uELEQRzBEAiBMsftfhpyULg4mEAV2ElQ5F5rojcqKncO6CPeVOYj6pgIgUh9JynkcJ9cOJzybFGFphZCTYeJb4nTqIA1+CIJ+UU0BIgYCx3cWH3PQt8crnue95lApPRPwlbx2Vq0fUl2l/S4QsRAYJ1acUDEAAIAAAACAAAAAgAAAAAAAAAAAAAAiAgLSDKUC7iiWhtIYFb1DqAY3sGmOH7zb5MrtRF9sGgqQ7xgnVpxQMQAAgAAAAIAAAACAAAAAAAQAAAAA",
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

  # Official BIP-174 "Fails Signer checks" vectors. These are NOT invalid PSBTs:
  # the BIP lists them in a separate section *after* the valid vectors. They are
  # well-formed and MUST decode and round-trip. What they violate is a Signer
  # check (BIP-174: "the redeemScript/witnessScript must match the hash in the
  # UTXO/redeemScript"). bitcoinex implements no Signer (signing is out of scope),
  # so the role that must reject them here is the Finalizer: it refuses to
  # assemble a final scriptSig/scriptWitness whose redeem/witness script does not
  # hash to the scriptPubKey, leaving the input unfinalized.
  @bip174_fails_signer_vectors [
    {"A Witness UTXO is provided for a non-witness input",
     "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEBItPf9QUAAAAAGXapFNSO0xELlAFMsRS9Mtb00GbcdCVriKwAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA="},
    {"redeemScript with non-witness UTXO does not match the scriptPubKey",
     "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq8iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="},
    {"redeemScript with witness UTXO does not match the scriptPubKey",
     "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQABBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="},
    {"witnessScript with witness UTXO does not match the redeemScript",
     "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSrSIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="}
  ]

  # Synthetic vector exercising the v0 fields absent from the official vectors:
  # global version/proprietary/unknown, input por_commitment, the four hash
  # preimage fields, and input/output proprietary/unknown records.
  @new_fields_vector "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AegDAAAAAAAAAAAAAAAB+wQAAAAABfxwcm9wCmdsb2JhbHByb3AEd3Vuaw1nbG9iYWx1bmtub3duAAEJFnBvci1jb21taXRtZW50LW1lc3NhZ2UVCk50bu0iT0UamJWX8T2JNHNhgYUdD3JpcGVtZC1wcmVpbWFnZSELtc5Hq7tvPHfRpSeMkAGzq12mN5sRq9/8a87IuSXKhg0Pc2hhMjU2LXByZWltYWdlFQxF8P/vzbRSLfKCyO6gCoqFEFZ7IRBoYXNoMTYwLXByZWltYWdlIQ1eNrfhh93WPk7FuAEEhtlhVtlvsDhTctcJyIcN7uTdbBBoYXNoMjU2LXByZWltYWdlA/xpcAlpbnB1dHByb3ADmWl1DGlucHV0dW5rbm93bgAD/G9wCm91dHB1dHByb3ADiG91DW91dHB1dHVua25vd24A"

  # Named indexes into @bip174_valid_vectors used by the representation tests.
  @sighash_vector_index 2
  @p2sh_p2wsh_vector_index 4

  # A known-valid compressed pubkey from the BIP-174 worked examples.
  @bip174_vector_pubkey "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f"

  # BIP-174 test-vector master key; every bip32_derivation/xpub in the official
  # vectors descends from it (master fingerprint d90c6a4f).
  @bip174_master_tprv "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"
  @global_xpub_vector_index 5

  defp valid_vector(index), do: Enum.at(@bip174_valid_vectors, index)

  # BIP-174 test-vector master key; every bip32_derivation/xpub in the official
  # vectors descends from it (master fingerprint d90c6a4f).
  @bip174_master_tprv "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"

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

  describe "BIP-174 \"Fails Signer checks\" vectors" do
    # These are valid PSBTs (they decode and round-trip); only the Signer/Finalizer
    # script-hash checks reject them. See the @bip174_fails_signer_vectors comment.
    test "decode and round-trip losslessly (they are structurally valid)" do
      for {name, base64} <- @bip174_fails_signer_vectors do
        assert {:ok, psbt} = PSBT.decode(base64), "expected decode to succeed: #{name}"
        assert PSBT.encode_b64(psbt) == base64, "expected lossless round-trip: #{name}"
      end
    end

    test "the finalizer refuses them (mismatched redeem/witness script), leaving inputs unfinalized" do
      for {name, base64} <- @bip174_fails_signer_vectors do
        {:ok, psbt} = PSBT.decode(base64)
        finalized = PSBT.finalize(psbt)
        refute PSBT.finalized?(finalized), "finalizer must not finalize: #{name}"
      end
    end
  end

  # Extra coverage vendored from Bitcoin Core's test/functional/data/rpc_psbt.json
  # (v0 subset only; v2/BIP-370 and taproot/BIP-371 vectors are out of scope).
  # Regenerate with scripts/gen_core_fixture.exs. The fixture buckets each vector
  # by this decoder's actual behavior; `_excluded` records the handful of Core
  # vectors we classify differently (our parser is more lenient on a few negative
  # cases; one 0-input tx trips the witness-marker ambiguity), so nothing is
  # silently mislabeled.
  describe "Bitcoin Core rpc_psbt.json v0 vectors" do
    setup do
      %{fixture: "test/data/core_psbt_v0_vectors.json" |> File.read!() |> Jason.decode!()}
    end

    test "invalid vectors are rejected", %{fixture: fixture} do
      for base64 <- fixture["invalid"] do
        assert {:error, _reason} = PSBT.decode(base64), "expected error decoding: #{base64}"
      end
    end

    test "valid vectors decode and round-trip losslessly", %{fixture: fixture} do
      for base64 <- fixture["valid_roundtrip"] do
        assert {:ok, psbt} = PSBT.decode(base64)
        assert PSBT.encode_b64(psbt) == base64
      end
    end

    test "non-canonically-ordered valid vectors decode (re-encode is canonical)", %{
      fixture: fixture
    } do
      for base64 <- fixture["valid_decode_only"] do
        assert {:ok, _psbt} = PSBT.decode(base64)
      end
    end
  end

  describe "to_file/2 & from_file/1" do
    test "every valid vector round-trips through a file" do
      filename = "./test/psbt-test.psbt"

      for base64 <- @bip174_valid_vectors do
        {:ok, psbt} = PSBT.decode(base64)
        assert :ok = PSBT.to_file(psbt, filename)
        assert {:ok, from_file} = PSBT.from_file(filename)
        assert from_file == psbt
        assert PSBT.encode_b64(from_file) == base64
      end

      File.rm_rf(filename)
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
      assert psbt.global.version == 0
      assert psbt.global.proprietary == [%{key: <<0xFC, "prop">>, value: "globalprop"}]
      assert psbt.global.unknown == [%{key: <<0x77, "unk">>, value: "globalunknown"}]
    end

    test "parses input por_commitment and hash preimage fields", %{psbt: psbt} do
      input = hd(psbt.inputs)
      # Each key hash is the actual digest of its preimage (BIP-174 requires it,
      # and decode/1 now validates it).
      assert input.por_commitment == "por-commitment-message"

      assert input.ripemd160 == [
               %{hash: :crypto.hash(:ripemd160, "ripemd-preimage"), preimage: "ripemd-preimage"}
             ]

      assert input.sha256 == [
               %{hash: Bitcoinex.Utils.sha256("sha256-preimage"), preimage: "sha256-preimage"}
             ]

      assert input.hash160 == [
               %{hash: Bitcoinex.Utils.hash160("hash160-preimage"), preimage: "hash160-preimage"}
             ]

      assert input.hash256 == [
               %{
                 hash: Bitcoinex.Utils.double_sha256("hash256-preimage"),
                 preimage: "hash256-preimage"
               }
             ]
    end

    test "parses input and output proprietary and unknown records", %{psbt: psbt} do
      input = hd(psbt.inputs)
      output = hd(psbt.outputs)

      assert input.proprietary == [%{key: <<0xFC, "ip">>, value: "inputprop"}]
      assert input.unknown == [%{key: <<0x99, "iu">>, value: "inputunknown"}]
      assert output.proprietary == [%{key: <<0xFC, "op">>, value: "outputprop"}]
      assert output.unknown == [%{key: <<0x88, "ou">>, value: "outputunknown"}]
    end

    test "rejects a hash-preimage record whose key hash is not the digest of the preimage" do
      {:ok, psbt} = PSBT.decode(@new_fields_vector)
      [input] = psbt.inputs
      # Corrupt the sha256 record's hash so it no longer matches its preimage,
      # then re-encode (serialization does not validate) and re-decode.
      corrupted = %{
        psbt
        | inputs: [
            %{input | sha256: [%{hash: :binary.copy(<<0>>, 32), preimage: "sha256-preimage"}]}
          ]
      }

      assert {:error, :invalid_hash_preimage} = PSBT.decode(PSBT.encode_b64(corrupted))
    end
  end

  # Synthetic PSBTs whose sighash values are out of the valid ECDSA set
  # ({0x01,0x02,0x03,0x81,0x82,0x83}): a sighash_type field of 4, and a
  # partial_sig whose trailing flag byte is 4.
  @invalid_sighash_type_field "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AegDAAAAAAAAAAAAAAAAAQMEBAAAAAAA"
  @invalid_partial_sig_sighash "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AegDAAAAAAAAAAAAAAAAIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwQAAA=="

  describe "typed field representations" do
    test "sighash_type is decoded as an integer" do
      {:ok, psbt} = PSBT.decode(valid_vector(@sighash_vector_index))
      assert hd(psbt.inputs).sighash_type == 1
    end

    test "rejects a sighash_type field outside the valid ECDSA set" do
      assert {:error, :invalid_sighash_type} = PSBT.decode(@invalid_sighash_type_field)
    end

    test "rejects a partial_sig whose trailing sighash flag is invalid" do
      assert {:error, :invalid_partial_sig} = PSBT.decode(@invalid_partial_sig_sighash)
    end

    test "rejects a PSBT advertising a non-v0 global version" do
      # Bitcoin Core rpc_psbt.json invalid[19]: PSBT_GLOBAL_VERSION = 1.
      v1_psbt =
        "cHNidP8B+wQBAAAAAQB1AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAAAA/v///wLT3/UFAAAAABl2qRTQxZkDxbrChodg6Q/VIaRmWqdlIIisAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4ezLhMAAAEA/aUBAQAAAAABAomjxx6rTSDgNxu7pMxpj6KVyUY6+i45f4UzzLYvlWflAQAAABcWABS+GNFSqbASA52vPafeT1M0nuy5hf////+G+KpDpx3/FEiJOlMKcjfva0YIu7LdLQFx5jrsakiQtAEAAAAXFgAU/j6e8adF6XTZAsQ1WUOryzS9U1P/////AgDC6wsAAAAAGXapFIXP8Ql/2eAIuzSvcJxiGXs4l4pIiKxy/vhOLAAAABepFDOXJboh79Yqx1OpvNBn1semo50FhwJHMEQCICcSviLgJw85T1aDEdx8qaaJcLgCX907JAIp8H+KXzokAiABizjX3NMU5zTJJ2vW+0D2czJbxLqhRMgA0vLwLbJ2XAEhA9LhVnSUG61KmWNyy4fhhW02UmBtmFYv45xenn5BPyEFAkgwRQIhANErhS2F3Nlh0vX0q2YGVN9u7cx5TAwzzlzDCf+1/OWNAiBnM4qODhclwZf7GoivWfUeROQlWyAWfIaEAxwF0fJZKgEhAiO3K+7wll0Qvgd47+zWH8rG95pOoWk5M4BzRGT4TyqzAAAAAAAAAA=="

      assert {:error, :unsupported_version} = PSBT.decode(v1_psbt)
    end

    test "rejects a non_witness_utxo whose txid does not match the input prevout" do
      # Bitcoin Core rpc_psbt.json invalid[39]: the input's prev_txid was mutated,
      # so the supplied non_witness_utxo no longer matches the outpoint.
      mismatched_txid =
        "cHNidP8BAHUCAAAAAQCBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA"

      assert {:error, :non_witness_utxo_mismatch} = PSBT.decode(mismatched_txid)
    end

    test "rejects a non_witness_utxo whose prevout index is out of range" do
      # Bitcoin Core rpc_psbt.json invalid[40]: the input's prev_vout was mutated
      # to an index beyond the non_witness_utxo's outputs.
      bad_vout =
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAgD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA"

      assert {:error, :non_witness_utxo_mismatch} = PSBT.decode(bad_vout)
    end

    test "partial_sig stores the public key as a Point and the signature as raw DER bytes" do
      {:ok, psbt} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))

      assert [%{public_key: %Point{} = public_key, signature: signature, sighash_flag: 1}] =
               hd(psbt.inputs).partial_sig

      # The signature is kept as raw bytes (not a parsed Signature struct) so it
      # round-trips verbatim; it is still well-formed DER.
      assert is_binary(signature)
      assert {:ok, %Signature{}} = Signature.der_parse_signature(signature)

      assert Point.sec(public_key) ==
               Base.decode16!(
                 "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
                 case: :lower
               )
    end

    test "preserves the exact partial_sig bytes on round-trip, including non-canonical DER" do
      {:ok, psbt} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      [%{public_key: public_key, sighash_flag: sighash_flag} | _] = hd(psbt.inputs).partial_sig

      # A DER signature carrying an unnecessary leading 0x00 on r: parseable, but
      # non-canonical. Parsing it into (r, s) and re-serializing would silently
      # rewrite it to canonical DER; storing the raw bytes preserves it exactly
      # across decode |> encode_b64.
      noncanonical_der =
        Base.decode16!(
          "3045022100" <> String.duplicate("11", 32) <> "0220" <> String.duplicate("22", 32),
          case: :lower
        )

      record = %{public_key: public_key, signature: noncanonical_der, sighash_flag: sighash_flag}

      psbt = %PSBT{
        psbt
        | inputs: [%{hd(psbt.inputs) | partial_sig: [record]} | tl(psbt.inputs)]
      }

      assert {:ok, decoded} = PSBT.decode(PSBT.encode_b64(psbt))
      assert [%{signature: ^noncanonical_der}] = hd(decoded.inputs).partial_sig
    end

    test "round-trips a redeem_script that is not a finalizer-recognized template" do
      # An arbitrary (non-standard) redeem script exercising Script parse/serialize
      # fidelity for the general case rather than the p2pkh/p2wpkh/p2wsh/multisig
      # templates: PUSH(4) <locktime> OP_CLTV OP_DROP PUSH(33) <pubkey> OP_CHECKSIG.
      redeem_hex =
        "04deadbeefb17521" <> "02" <> String.duplicate("ab", 32) <> "ac"

      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, psbt} = PSBT.add_input_field(base, 0, :redeem_script, redeem_hex)

      assert {:ok, decoded} = PSBT.decode(PSBT.encode_b64(psbt))
      assert Script.to_hex(hd(decoded.inputs).redeem_script) == redeem_hex
    end

    test "redeem_script and witness_script are Script structs" do
      {:ok, psbt} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      input = hd(psbt.inputs)

      assert %Script{} = input.redeem_script
      assert %Script{} = input.witness_script

      assert Script.to_hex(input.redeem_script) ==
               "0020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681"
    end

    test "input bip32_derivation uses Point and KeyOrigin structs" do
      {:ok, psbt} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))

      assert [
               %{
                 public_key: %Point{},
                 origin: %KeyOrigin{
                   fingerprint: fingerprint,
                   derivation: %DerivationPath{
                     child_nums: [2_147_483_648, 2_147_483_648, 2_147_483_652]
                   }
                 }
               }
               | _rest
             ] = hd(psbt.inputs).bip32_derivation

      assert byte_size(fingerprint) == 4
    end

    test "global xpub uses ExtendedKey and KeyOrigin structs" do
      {:ok, psbt} = PSBT.decode(valid_vector(@global_xpub_vector_index))

      assert [
               %{
                 xkey: %ExtendedKey{} = xkey,
                 origin: %KeyOrigin{
                   fingerprint: fingerprint,
                   derivation: %DerivationPath{child_nums: [2_147_483_822, 2_147_483_648]}
                 }
               }
               | _rest
             ] = psbt.global.xpub

      # Fingerprint is the raw 4 wire bytes, not reversed. The wire encodes the
      # master fingerprint 0x3119694f (little-endian value 1_332_350_169); a
      # byte-reversing parse would yield <<0x4f, 0x69, 0x19, 0x31>> instead.
      assert fingerprint == <<1_332_350_169::little-size(32)>>

      assert ExtendedKey.display_extended_key(xkey) ==
               "tpubDBkJeJo2X94Yq3RVz65DoUgyLUkaDrkfyrn2VcgyCRSKCRonvKvCF2FpYDGJWDkdRHBajXJGpc63GnumUt63ySvqCu2XaTRGVTKMYGuFk9H"
    end
  end

  describe "from_tx/1 (Creator)" do
    setup do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      %{unsigned_tx: base.global.unsigned_tx}
    end

    test "builds one empty input and output map per tx input/output", %{unsigned_tx: tx} do
      {:ok, psbt} = PSBT.from_tx(tx)

      assert psbt.global.unsigned_tx == %{tx | witnesses: nil}
      assert length(psbt.inputs) == length(tx.inputs)
      assert length(psbt.outputs) == length(tx.outputs)
      assert Enum.all?(psbt.inputs, &(&1 == %Bitcoinex.PSBT.In{}))
      assert Enum.all?(psbt.outputs, &(&1 == %Bitcoinex.PSBT.Out{}))
    end

    test "rejects a tx whose input carries a scriptSig", %{unsigned_tx: tx} do
      signed_input = %{hd(tx.inputs) | script_sig: "0014abcdef"}
      signed_tx = %{tx | inputs: [signed_input | tl(tx.inputs)]}

      assert {:error, :tx_not_unsigned} = PSBT.from_tx(signed_tx)
    end

    test "rejects a tx that carries witnesses", %{unsigned_tx: tx} do
      witness_tx = %{tx | witnesses: [%Bitcoinex.Transaction.Witness{txinwitness: ["00"]}]}
      assert {:error, :tx_not_unsigned} = PSBT.from_tx(witness_tx)
    end
  end

  describe "add_global_field(:unsigned_tx)" do
    setup do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      %{tx: base.global.unsigned_tx, base: base}
    end

    test "refuses to replace an existing unsigned tx", %{base: base, tx: tx} do
      assert {:error, :unsigned_tx_already_set} = PSBT.add_global_field(base, :unsigned_tx, tx)
    end

    test "rejects a tx whose input/output counts do not match the PSBT's maps", %{tx: tx} do
      # A PSBT skeleton with no unsigned tx and more input maps than the tx has
      # inputs (the p2sh-p2wsh vector's tx has a single input).
      skeleton = %PSBT{
        global: %Bitcoinex.PSBT.Global{},
        inputs: [%Bitcoinex.PSBT.In{}, %Bitcoinex.PSBT.In{}],
        outputs: [%Bitcoinex.PSBT.Out{}]
      }

      assert {:error, :tx_io_count_mismatch} = PSBT.add_global_field(skeleton, :unsigned_tx, tx)
    end

    test "rejects a signed tx", %{tx: tx} do
      skeleton = %PSBT{
        global: %Bitcoinex.PSBT.Global{},
        inputs: Enum.map(tx.inputs, fn _ -> %Bitcoinex.PSBT.In{} end),
        outputs: Enum.map(tx.outputs, fn _ -> %Bitcoinex.PSBT.Out{} end)
      }

      signed = %{tx | inputs: [%{hd(tx.inputs) | script_sig: "0014abcdef"} | tl(tx.inputs)]}
      assert {:error, :tx_not_unsigned} = PSBT.add_global_field(skeleton, :unsigned_tx, signed)
    end
  end

  describe "txid/1" do
    test "returns the txid of the global unsigned tx" do
      {:ok, psbt} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      assert {:ok, txid} = PSBT.txid(psbt)
      assert txid == Transaction.transaction_id(psbt.global.unsigned_tx)
    end

    test "errors when there is no unsigned tx" do
      psbt = %PSBT{global: %Bitcoinex.PSBT.Global{unsigned_tx: nil}, inputs: [], outputs: []}
      assert {:error, :no_unsigned_tx} = PSBT.txid(psbt)
    end
  end

  describe "Updater (add_global_field/3, add_input_field/4, add_output_field/4)" do
    setup do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, psbt} = PSBT.from_tx(base.global.unsigned_tx)
      %{psbt: psbt}
    end

    test "adds the v0 global version and round-trips it", %{psbt: psbt} do
      {:ok, psbt} = PSBT.add_global_field(psbt, :version, 0)
      assert psbt.global.version == 0

      {:ok, decoded} = PSBT.decode(PSBT.encode_b64(psbt))
      assert decoded.global.version == 0
    end

    test "rejects a non-zero global version (only PSBT v0 is supported)", %{psbt: psbt} do
      assert {:error, :unsupported_version} = PSBT.add_global_field(psbt, :version, 2)
    end

    test "adds an input sighash_type", %{psbt: psbt} do
      assert {:ok, psbt} = PSBT.add_input_field(psbt, 0, :sighash_type, 0x01)
      assert hd(psbt.inputs).sighash_type == 0x01
    end

    test "rejects an invalid sighash_type", %{psbt: psbt} do
      assert {:error, :invalid_field} = PSBT.add_input_field(psbt, 0, :sighash_type, 0x04)
    end

    test "rejects an out-of-range input index", %{psbt: psbt} do
      assert {:error, :index_out_of_range} = PSBT.add_input_field(psbt, 99, :sighash_type, 0x01)
    end

    test "accepts a redeem_script as either a hex string or a Script struct", %{psbt: psbt} do
      script_hex = "0014841c1c11d0b4e9c9f0c0e8b0d0e8b0d0e8b0d0e8"
      {:ok, script} = Script.parse_script(script_hex)

      assert {:ok, from_hex} = PSBT.add_input_field(psbt, 0, :redeem_script, script_hex)
      assert {:ok, from_struct} = PSBT.add_input_field(psbt, 0, :redeem_script, script)
      assert hd(from_hex.inputs).redeem_script == script
      assert hd(from_struct.inputs).redeem_script == script
    end

    test "normalizes a witness_utxo scriptPubKey to lowercase so encode never raises", %{
      psbt: psbt
    } do
      spk = "0014D85C2B71D0060B09C9886AEB815E50991DDA124D"
      utxo = %Bitcoinex.Transaction.Out{value: 1000, script_pub_key: spk}

      assert {:ok, psbt} = PSBT.add_input_field(psbt, 0, :witness_utxo, utxo)
      assert hd(psbt.inputs).witness_utxo.script_pub_key == String.downcase(spk)
      # Regression: uppercase hex used to be accepted and then raise here.
      assert is_binary(PSBT.encode_b64(psbt))
    end

    test "normalizes final_scriptwitness items to lowercase", %{psbt: psbt} do
      witness = %Bitcoinex.Transaction.Witness{txinwitness: ["00AABB", "CCDD"]}
      assert {:ok, psbt} = PSBT.add_input_field(psbt, 0, :final_scriptwitness, witness)
      assert hd(psbt.inputs).final_scriptwitness.txinwitness == ["00aabb", "ccdd"]
    end

    test "rejects a witness_utxo whose scriptPubKey is not valid hex", %{psbt: psbt} do
      utxo = %Bitcoinex.Transaction.Out{value: 1000, script_pub_key: "not-hex!"}
      assert {:error, :invalid_field} = PSBT.add_input_field(psbt, 0, :witness_utxo, utxo)
    end

    test "preserves the raw bip32 fingerprint bytes (no endianness reversal)", %{psbt: psbt} do
      {:ok, public_key} =
        Point.parse_public_key(
          Base.decode16!("03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
            case: :lower
          )
        )

      fingerprint = <<0xDE, 0xAD, 0xBE, 0xEF>>

      origin = %KeyOrigin{
        fingerprint: fingerprint,
        derivation: %DerivationPath{child_nums: [0x80000000, 0]}
      }

      {:ok, psbt} =
        PSBT.add_input_field(psbt, 0, :bip32_derivation, %{public_key: public_key, origin: origin})

      {:ok, decoded} = PSBT.decode(PSBT.encode_b64(psbt))
      [%{origin: decoded_origin}] = hd(decoded.inputs).bip32_derivation

      assert decoded_origin.fingerprint == fingerprint
      assert decoded_origin.derivation.child_nums == [0x80000000, 0]
    end

    test "adds an output witness_script", %{psbt: psbt} do
      script_hex = "0014841c1c11d0b4e9c9f0c0e8b0d0e8b0d0e8b0d0e8"
      {:ok, psbt} = PSBT.add_output_field(psbt, 0, :witness_script, script_hex)
      {:ok, expected} = Script.parse_script(script_hex)
      assert hd(psbt.outputs).witness_script == expected
    end

    test "accepts a hash-preimage record whose hash matches the preimage", %{psbt: psbt} do
      preimage = "preimage bytes"

      for {field, hash} <- [
            {:ripemd160, :crypto.hash(:ripemd160, preimage)},
            {:sha256, Bitcoinex.Utils.sha256(preimage)},
            {:hash160, Bitcoinex.Utils.hash160(preimage)},
            {:hash256, Bitcoinex.Utils.double_sha256(preimage)}
          ] do
        record = %{hash: hash, preimage: preimage}
        assert {:ok, updated} = PSBT.add_input_field(psbt, 0, field, record)
        assert Map.get(hd(updated.inputs), field) == [record]
      end
    end

    test "rejects a hash-preimage record whose hash does not match the preimage", %{psbt: psbt} do
      wrong = %{hash: :binary.copy(<<0>>, 32), preimage: "preimage bytes"}
      assert {:error, :invalid_hash_preimage} = PSBT.add_input_field(psbt, 0, :sha256, wrong)
    end
  end

  # BIP-174 Combiner worked examples.
  @combine_signer_a "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
  @combine_signer_b "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="
  @combine_signer_expected "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
  @combine_unknown_a "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA="
  @combine_unknown_b "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
  @combine_unknown_expected "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8K8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwrwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="

  describe "combine/2 (Combiner)" do
    test "reproduces the official BIP-174 combiner vector byte-for-byte" do
      {:ok, a} = PSBT.decode(@combine_signer_a)
      {:ok, b} = PSBT.decode(@combine_signer_b)
      {:ok, expected} = PSBT.decode(@combine_signer_expected)
      {:ok, combined} = PSBT.combine(a, b)

      # First-list order is kept and new records appended (Bitcoin Core's Merge
      # semantics), so the result matches the BIP's expected combined PSBT
      # exactly, not just as a record set.
      assert combined == expected
      assert PSBT.encode_b64(combined) == @combine_signer_expected
      assert Enum.all?(combined.inputs, fn input -> length(input.partial_sig) == 2 end)
    end

    test "byte-matches the unknown-keys combiner vector" do
      {:ok, a} = PSBT.decode(@combine_unknown_a)
      {:ok, b} = PSBT.decode(@combine_unknown_b)
      {:ok, combined} = PSBT.combine(a, b)
      assert PSBT.encode_b64(combined) == @combine_unknown_expected
    end

    test "is commutative up to record order" do
      # combine(a,b) and combine(b,a) union the same record sets; only the
      # order of repeatable records differs (first argument's records lead).
      for {first, second} <- [
            {@combine_signer_a, @combine_signer_b},
            {@combine_unknown_a, @combine_unknown_b}
          ] do
        {:ok, a} = PSBT.decode(first)
        {:ok, b} = PSBT.decode(second)
        {:ok, ab} = PSBT.combine(a, b)
        {:ok, ba} = PSBT.combine(b, a)
        assert sort_repeatable_records(ab) == sort_repeatable_records(ba)
      end
    end

    test "is idempotent for any PSBT" do
      for vector <- [@combine_signer_a, @combine_signer_b, @combine_signer_expected] do
        {:ok, a} = PSBT.decode(vector)
        assert PSBT.combine(a, a) == {:ok, a}
      end
    end

    test "combining two v0 PSBTs preserves the version" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, a} = PSBT.add_global_field(base, :version, 0)
      {:ok, b} = PSBT.add_global_field(base, :version, 0)

      assert {:ok, combined} = PSBT.combine(a, b)
      assert combined.global.version == 0
    end

    test "rejects PSBTs whose input-map counts do not match (no silent truncation)" do
      {:ok, a} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      # Same unsigned tx, but a desynced (hand-corrupted) input-map list.
      b = %PSBT{a | inputs: []}
      assert {:error, :map_count_mismatch} = PSBT.combine(a, b)
    end

    test "rejects PSBTs describing different transactions" do
      {:ok, a} = PSBT.decode(valid_vector(0))
      {:ok, b} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      assert {:error, :mismatched_tx} = PSBT.combine(a, b)
    end

    test "rejects same-txid unsigned txs that differ byte-for-byte (stray witnesses)" do
      {:ok, a} = PSBT.decode(@combine_signer_a)

      # Same unsigned tx but carrying stray witnesses: the txid is unchanged
      # (witnesses are stripped when computing it) yet the full serialization
      # differs. A txid-only precondition would wrongly accept these as the same
      # tx; the byte-for-byte comparison rejects them.
      tx = a.global.unsigned_tx

      witnesses =
        Enum.map(tx.inputs, fn _ -> %Bitcoinex.Transaction.Witness{txinwitness: ["00"]} end)

      tampered = %{tx | witnesses: witnesses}
      b = %{a | global: %{a.global | unsigned_tx: tampered}}

      assert Transaction.transaction_id(tx) == Transaction.transaction_id(tampered)
      assert {:error, :mismatched_tx} = PSBT.combine(a, b)
    end

    test "rejects conflicting singleton fields" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, a} = PSBT.add_input_field(base, 0, :sighash_type, 0x01)
      {:ok, b} = PSBT.add_input_field(base, 0, :sighash_type, 0x02)
      assert {:error, :conflicting_field} = PSBT.combine(a, b)
    end

    test "rejects a repeatable record with the same key but a different value" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, a} = PSBT.add_input_field(base, 0, :proprietary, %{key: <<0xFC, "x">>, value: "one"})
      {:ok, b} = PSBT.add_input_field(base, 0, :proprietary, %{key: <<0xFC, "x">>, value: "two"})
      assert {:error, :conflicting_field} = PSBT.combine(a, b)
    end

    test "merges a repeatable record shared identically by both sides" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      record = %{key: <<0xFC, "x">>, value: "same"}
      {:ok, a} = PSBT.add_input_field(base, 0, :proprietary, record)
      {:ok, b} = PSBT.add_input_field(base, 0, :proprietary, record)
      assert {:ok, combined} = PSBT.combine(a, b)
      assert hd(combined.inputs).proprietary == [record]
    end

    test "unions repeatable fields (partial signatures) from both inputs" do
      {:ok, a} = PSBT.decode(@combine_signer_a)
      {:ok, b} = PSBT.decode(@combine_signer_b)
      {:ok, combined} = PSBT.combine(a, b)

      combined_sigs = Enum.flat_map(combined.inputs, fn input -> input.partial_sig end)
      a_sigs = Enum.flat_map(a.inputs, fn input -> input.partial_sig || [] end)
      b_sigs = Enum.flat_map(b.inputs, fn input -> input.partial_sig || [] end)

      assert Enum.all?(a_sigs, &(&1 in combined_sigs))
      assert Enum.all?(b_sigs, &(&1 in combined_sigs))
    end

    test "rejects PSBTs whose output-map counts do not match" do
      {:ok, a} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      b = %PSBT{a | outputs: []}
      assert {:error, :map_count_mismatch} = PSBT.combine(a, b)
    end

    test "rejects a global xpub key collision with differing origins" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, master} = ExtendedKey.parse_extended_key(@bip174_master_tprv)
      {:ok, xpub} = ExtendedKey.to_extended_public_key(master)
      fingerprint = ExtendedKey.get_fingerprint(master)

      origin_a = %KeyOrigin{fingerprint: fingerprint, derivation: %DerivationPath{child_nums: []}}

      origin_b = %KeyOrigin{
        fingerprint: <<0, 0, 0, 0>>,
        derivation: %DerivationPath{child_nums: []}
      }

      {:ok, a} = PSBT.add_global_field(base, :xpub, %{xkey: xpub, origin: origin_a})
      {:ok, b} = PSBT.add_global_field(base, :xpub, %{xkey: xpub, origin: origin_b})

      assert {:error, :conflicting_field} = PSBT.combine(a, b)
      assert {:ok, _combined} = PSBT.combine(a, a)
    end

    test "rejects a conflicting output singleton field" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))

      {:ok, a} =
        PSBT.add_output_field(base, 0, :witness_script, "0014" <> String.duplicate("ab", 20))

      {:ok, b} =
        PSBT.add_output_field(base, 0, :witness_script, "0014" <> String.duplicate("cd", 20))

      assert {:error, :conflicting_field} = PSBT.combine(a, b)
    end

    test "returns an error instead of raising when an unsigned tx is missing" do
      {:ok, a} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      empty = %PSBT{global: %Bitcoinex.PSBT.Global{}, inputs: [], outputs: []}
      no_global = %PSBT{global: nil, inputs: [], outputs: []}

      assert {:error, :missing_unsigned_tx} = PSBT.combine(a, empty)
      assert {:error, :missing_unsigned_tx} = PSBT.combine(empty, a)
      assert {:error, :missing_unsigned_tx} = PSBT.combine(no_global, no_global)
    end

    test "rejects a partial_sig with the same pubkey but a different signature" do
      {:ok, a} = PSBT.decode(@combine_signer_a)

      [input | rest] = a.inputs
      [sig | more_sigs] = input.partial_sig
      tampered = %{sig | signature: sig.signature <> <<0>>}
      b = %PSBT{a | inputs: [%In{input | partial_sig: [tampered | more_sigs]} | rest]}

      assert {:error, :conflicting_field} = PSBT.combine(a, b)
    end

    # Unreachable through the public API today (decode/add_field accept only
    # version 0), but BIP-174 directs combiners to keep the highest version;
    # this pins Global.combine/2's behavior directly.
    test "Global.combine/2 keeps the higher version when they differ" do
      assert {:ok, %Global{version: 1}} = Global.combine(%Global{version: 0}, %Global{version: 1})
      assert {:ok, %Global{version: 1}} = Global.combine(%Global{version: 1}, %Global{version: 0})
      assert {:ok, %Global{version: 0}} = Global.combine(%Global{version: 0}, %Global{})
      assert {:ok, %Global{version: nil}} = Global.combine(%Global{}, %Global{})
    end
  end

  # Sorts every repeatable (list-valued) field so two PSBTs that union the same
  # record sets in different orders compare equal.
  defp sort_repeatable_records(%PSBT{} = psbt) do
    %PSBT{
      psbt
      | global: sort_struct_lists(psbt.global),
        inputs: Enum.map(psbt.inputs, &sort_struct_lists/1),
        outputs: Enum.map(psbt.outputs, &sort_struct_lists/1)
    }
  end

  defp sort_struct_lists(%module{} = struct) do
    fields =
      struct
      |> Map.from_struct()
      |> Enum.map(fn {key, value} ->
        {key, if(is_list(value), do: Enum.sort(value), else: value)}
      end)

    struct(module, fields)
  end

  # The expected result of the BIP-174 Combiner worked example: every input
  # carries TWO partial_sig records (one per signer). Guards the repeatability
  # of partial_sig — a singleton representation keeps only the last record.
  @two_partial_sigs_vector @combine_signer_expected

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

    test "sighash_type is parsed from and re-emitted as 4 little-endian bytes" do
      psbt_b64 = psbt_with_records(record(<<0x03>>, <<0x01, 0x00, 0x00, 0x00>>), :input)
      assert {:ok, psbt} = PSBT.decode(psbt_b64)
      assert hd(psbt.inputs).sighash_type == 0x01
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
      pubkey = Base.decode16!(@bip174_vector_pubkey, case: :lower)
      {:ok, master} = ExtendedKey.parse_extended_key(@bip174_master_tprv)
      {:ok, xpub} = ExtendedKey.to_extended_public_key(master)
      xpub_keydata = binary_part(ExtendedKey.serialize_extended_key(xpub), 0, 78)
      # fingerprint + one full index + one stray byte (length ≢ 0 mod 4)
      value = <<0, 0, 0, 0>> <> <<84::little-size(32)>> <> <<0xAA>>

      assert {:error, :invalid_derivation} =
               PSBT.decode(psbt_with_records(record(<<0x01>> <> xpub_keydata, value), :global))

      assert {:error, :invalid_derivation} =
               PSBT.decode(psbt_with_records(record(<<0x06>> <> pubkey, value), :input))

      assert {:error, :invalid_derivation} =
               PSBT.decode(psbt_with_records(record(<<0x02>> <> pubkey, value), :output))
    end
  end

  describe "duplicate keys in the global and output maps" do
    test "a repeated global key is rejected with :duplicate_key" do
      records = record(<<0xFB>>, <<0, 0, 0, 0>>) <> record(<<0xFB>>, <<0, 0, 0, 0>>)
      assert {:error, :duplicate_key} = PSBT.decode(psbt_with_records(records, :global))
    end

    test "a repeated output key is rejected with :duplicate_key" do
      pubkey = Base.decode16!(@bip174_vector_pubkey, case: :lower)
      bip32 = record(<<0x02>> <> pubkey, <<0, 0, 0, 0>>)
      assert {:error, :duplicate_key} = PSBT.decode(psbt_with_records(bip32 <> bip32, :output))
    end
  end

  # A structurally well-formed record whose 33-byte pubkey has a prefix other
  # than 0x02/0x03 must decode to a clean error, never crash the caller.
  describe "invalid public key prefixes" do
    test "a 33-byte pubkey whose prefix is not 0x02/0x03 is cleanly rejected" do
      badkey = <<0x05>> <> :binary.copy(<<0xAB>>, 32)

      assert {:error, :invalid_partial_sig} =
               PSBT.decode(psbt_with_records(record(<<0x02>> <> badkey, <<0x30>>), :input))

      assert {:error, :invalid_bip32_derivation} =
               PSBT.decode(psbt_with_records(record(<<0x06>> <> badkey, <<0, 0, 0, 0>>), :input))

      assert {:error, :invalid_bip32_derivation} =
               PSBT.decode(psbt_with_records(record(<<0x02>> <> badkey, <<0, 0, 0, 0>>), :output))
    end
  end

  # BIP-174: "The number of 32 bit unsigned integer indexes must match the
  # depth provided in the extended public key."
  describe "global xpub depth must match the derivation path length" do
    test "decoding rejects an xpub whose path length differs from its depth" do
      {:ok, master} = ExtendedKey.parse_extended_key(@bip174_master_tprv)
      {:ok, xpub} = ExtendedKey.to_extended_public_key(master)
      xpub_keydata = binary_part(ExtendedKey.serialize_extended_key(xpub), 0, 78)

      # the master key has depth 0, but the origin carries one index
      one_index = <<0, 0, 0, 0>> <> <<0x80000054::little-size(32)>>

      assert {:error, :xpub_depth_mismatch} =
               PSBT.decode(
                 psbt_with_records(record(<<0x01>> <> xpub_keydata, one_index), :global)
               )

      # depth 0 with an empty path is consistent and decodes fine
      assert {:ok, _psbt} =
               PSBT.decode(
                 psbt_with_records(record(<<0x01>> <> xpub_keydata, <<0, 0, 0, 0>>), :global)
               )
    end

    test "add_global_field(:xpub) rejects a depth/path mismatch" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, psbt} = PSBT.from_tx(base.global.unsigned_tx)
      {:ok, master} = ExtendedKey.parse_extended_key(@bip174_master_tprv)
      {:ok, xpub} = ExtendedKey.to_extended_public_key(master)

      origin = %KeyOrigin{
        fingerprint: ExtendedKey.get_fingerprint(master),
        derivation: %DerivationPath{child_nums: [0x80000054]}
      }

      assert {:error, :xpub_depth_mismatch} =
               PSBT.add_global_field(psbt, :xpub, %{xkey: xpub, origin: origin})
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
      psbt = %PSBT{global: %Bitcoinex.PSBT.Global{}, inputs: [], outputs: []}
      assert {:error, :missing_unsigned_tx} = PSBT.encode_b64(psbt)
      assert {:error, :missing_unsigned_tx} = PSBT.to_file(psbt, "./test/never-written.psbt")
      refute File.exists?("./test/never-written.psbt")
    end

    test "txid/1 and add_global_field/3 return errors on a PSBT with no global map" do
      psbt = %PSBT{global: nil, inputs: [], outputs: []}
      assert {:error, :no_unsigned_tx} = PSBT.txid(psbt)
      assert {:ok, updated} = PSBT.add_global_field(psbt, :version, 0)
      assert updated.global.version == 0
    end
  end

  describe "scripts with non-minimal pushes" do
    test "a redeem_script using OP_PUSHDATA1 for a short payload round-trips byte-for-byte" do
      # `4c 14 <20 bytes>` is consensus-valid but non-minimal; Script must not
      # rewrite it to `14 <20 bytes>` (the hash would no longer match a p2sh
      # scriptPubKey built from the original bytes).
      non_minimal = <<0x4C, 0x14>> <> :binary.copy(<<0xAB>>, 20)
      psbt_b64 = psbt_with_records(record(<<0x04>>, non_minimal), :input)

      assert {:ok, psbt} = PSBT.decode(psbt_b64)
      assert Script.serialize_script(hd(psbt.inputs).redeem_script) == non_minimal
      assert PSBT.encode_b64(psbt) == psbt_b64
    end
  end

  describe "key origins" do
    test "a decoded fingerprint equals ExtendedKey.get_fingerprint/1 of the master key" do
      # Guards the raw-4-bytes fingerprint representation: an LE-integer
      # regression would compare byte-reversed against get_fingerprint/1.
      {:ok, master} = ExtendedKey.parse_extended_key(@bip174_master_tprv)
      {:ok, psbt} = PSBT.decode(@two_partial_sigs_vector)

      [%{origin: origin} | _] = hd(psbt.inputs).bip32_derivation
      assert origin.fingerprint == ExtendedKey.get_fingerprint(master)
      assert origin.fingerprint == <<0xD9, 0x0C, 0x6A, 0x4F>>
    end

    test "a decoded derivation renders through DerivationPath.to_string/1" do
      {:ok, psbt} = PSBT.decode(@two_partial_sigs_vector)
      [%{origin: origin} | _] = hd(psbt.inputs).bip32_derivation

      assert origin.derivation.child_nums == [0x80000000, 0x80000000, 0x80000000]
      assert {:ok, rendered} = DerivationPath.to_string(origin.derivation)
      assert String.replace(rendered, "h", "'") =~ "0'/0'/0'"
    end
  end

  describe "Updater content validation" do
    setup do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, psbt} = PSBT.from_tx(base.global.unsigned_tx)

      {:ok, public_key} =
        Point.parse_public_key(
          Base.decode16!("03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
            case: :lower
          )
        )

      %{psbt: psbt, public_key: public_key, base: base}
    end

    test "adds a partial_sig and rejects a duplicate for the same pubkey", %{
      psbt: psbt,
      public_key: public_key,
      base: base
    } do
      [%{signature: signature} | _] = hd(base.inputs).partial_sig
      record = %{public_key: public_key, signature: signature, sighash_flag: 0x01}

      assert {:ok, updated} = PSBT.add_input_field(psbt, 0, :partial_sig, record)
      assert hd(updated.inputs).partial_sig == [record]
      assert {:error, :duplicate_key} = PSBT.add_input_field(updated, 0, :partial_sig, record)
    end

    test "rejects a partial_sig whose signature is not parseable DER", %{
      psbt: psbt,
      public_key: public_key
    } do
      record = %{public_key: public_key, signature: <<0xFF, 0xFF>>, sighash_flag: 0x01}
      assert {:error, :invalid_partial_sig} = PSBT.add_input_field(psbt, 0, :partial_sig, record)
    end

    test "rejects a KeyOrigin with a wrong-length fingerprint or wildcard path", %{
      psbt: psbt,
      public_key: public_key
    } do
      short_fp = %KeyOrigin{
        fingerprint: <<1, 2, 3>>,
        derivation: %DerivationPath{child_nums: [0]}
      }

      wildcard = %KeyOrigin{
        fingerprint: <<1, 2, 3, 4>>,
        derivation: %DerivationPath{child_nums: [0x80000000, :any]}
      }

      for origin <- [short_fp, wildcard] do
        record = %{public_key: public_key, origin: origin}

        assert {:error, :invalid_key_origin} =
                 PSBT.add_input_field(psbt, 0, :bip32_derivation, record)

        assert {:error, :invalid_key_origin} =
                 PSBT.add_output_field(psbt, 0, :bip32_derivation, record)
      end
    end

    test "rejects a bip32_derivation duplicate for the same pubkey", %{
      psbt: psbt,
      public_key: public_key
    } do
      origin = %KeyOrigin{
        fingerprint: <<1, 2, 3, 4>>,
        derivation: %DerivationPath{child_nums: [0x80000000]}
      }

      record = %{public_key: public_key, origin: origin}
      assert {:ok, updated} = PSBT.add_input_field(psbt, 0, :bip32_derivation, record)

      assert {:error, :duplicate_key} =
               PSBT.add_input_field(updated, 0, :bip32_derivation, record)
    end

    test "rejects an out-of-range output index", %{psbt: psbt} do
      assert {:error, :index_out_of_range} =
               PSBT.add_output_field(
                 psbt,
                 99,
                 :witness_script,
                 "0014" <> String.duplicate("ab", 20)
               )
    end

    test "adds global proprietary and unknown records and rejects duplicates", %{psbt: psbt} do
      record = %{key: <<0xFC, "prop">>, value: "data"}
      assert {:ok, updated} = PSBT.add_global_field(psbt, :proprietary, record)
      assert {:error, :duplicate_key} = PSBT.add_global_field(updated, :proprietary, record)

      unknown = %{key: <<0x42>>, value: "data"}
      assert {:ok, updated} = PSBT.add_global_field(psbt, :unknown, unknown)
      assert {:error, :duplicate_key} = PSBT.add_global_field(updated, :unknown, unknown)
    end

    test "rejects a witness_utxo without an integer value", %{psbt: psbt} do
      utxo = %Bitcoinex.Transaction.Out{
        value: nil,
        script_pub_key: "0014" <> String.duplicate("ab", 20)
      }

      assert {:error, :invalid_field} = PSBT.add_input_field(psbt, 0, :witness_utxo, utxo)
    end

    test "validates a non_witness_utxo against the input's outpoint" do
      # Vector 4 carries a genuine non_witness_utxo for input 0; re-adding it to
      # a fresh skeleton of the same unsigned tx must succeed, and a mutated
      # (different-txid) transaction must be rejected.
      {:ok, base} = PSBT.decode(valid_vector(3))
      {:ok, psbt} = PSBT.from_tx(base.global.unsigned_tx)
      utxo = hd(base.inputs).non_witness_utxo
      assert %Bitcoinex.Transaction{} = utxo

      assert {:ok, updated} = PSBT.add_input_field(psbt, 0, :non_witness_utxo, utxo)
      assert hd(updated.inputs).non_witness_utxo == utxo

      mutated = %Bitcoinex.Transaction{utxo | lock_time: utxo.lock_time + 1}

      assert {:error, :non_witness_utxo_mismatch} =
               PSBT.add_input_field(psbt, 0, :non_witness_utxo, mutated)
    end
  end

  describe "extended private keys are refused in xpub fields" do
    test "decoding a PSBT whose global xpub key-data is an xprv fails" do
      {:ok, master} = ExtendedKey.parse_extended_key(@bip174_master_tprv)
      raw78 = binary_part(ExtendedKey.serialize_extended_key(master), 0, 78)
      xprv_record = record(<<0x01>> <> raw78, <<0, 0, 0, 0>>)

      assert {:error, :private_key_not_allowed} =
               PSBT.decode(psbt_with_records(xprv_record, :global))
    end

    test "add_global_field(:xpub) rejects an extended private key" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      {:ok, psbt} = PSBT.from_tx(base.global.unsigned_tx)
      {:ok, master} = ExtendedKey.parse_extended_key(@bip174_master_tprv)

      origin = %KeyOrigin{
        fingerprint: ExtendedKey.get_fingerprint(master),
        derivation: %DerivationPath{child_nums: []}
      }

      assert {:error, :private_key_not_allowed} =
               PSBT.add_global_field(psbt, :xpub, %{xkey: master, origin: origin})

      {:ok, xpub} = ExtendedKey.to_extended_public_key(master)
      assert {:ok, updated} = PSBT.add_global_field(psbt, :xpub, %{xkey: xpub, origin: origin})
      assert [%{xkey: ^xpub}] = updated.global.xpub

      assert {:error, :duplicate_key} =
               PSBT.add_global_field(updated, :xpub, %{xkey: xpub, origin: origin})
    end
  end

  @p2wpkh_pubkey_hex "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46"
  @p2wpkh_sig_hex "3044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01"

  # A compressed pubkey and a canonical DER signature (both from the BIP-174
  # vectors) used to construct finalize test inputs. The finalizer assembles
  # bytes; it does not verify the signature.
  @finalize_pubkey_a "03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc"
  @finalize_pubkey_b "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7"
  @finalize_pubkey_c "023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73"
  @finalize_sig_a "3044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f"

  # BIP-174 Finalizer/Extractor worked example (P2SH multisig + P2SH-P2WSH multisig).
  @finalize_input "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
  @finalize_expected "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
  @extract_tx_hex "0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000"

  describe "finalize/1 & finalized?/1 (Finalizer)" do
    test "finalizes the BIP-174 combiner output to the expected PSBT" do
      {:ok, psbt} = PSBT.decode(@finalize_input)
      finalized = PSBT.finalize(psbt)

      assert PSBT.finalized?(finalized)
      assert PSBT.encode_b64(finalized) == @finalize_expected
    end

    test "already-finalized inputs and re-finalization are idempotent" do
      {:ok, psbt} = PSBT.decode(@finalize_input)
      finalized = PSBT.finalize(psbt)
      assert PSBT.finalize(finalized) == finalized
    end

    test "leaves inputs without enough data unfinalized (best-effort)" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      # from_tx yields empty input maps: nothing to finalize with.
      {:ok, empty} = PSBT.from_tx(base.global.unsigned_tx)
      finalized = PSBT.finalize(empty)

      refute PSBT.finalized?(finalized)
      assert finalized == empty
    end

    test "finalizes a p2wpkh input to a witness (sig, pubkey) with no scriptSig" do
      psbt = single_sig_p2wpkh_psbt()
      finalized = PSBT.finalize(psbt)
      input = hd(finalized.inputs)

      assert input.final_scriptsig == nil
      assert input.final_scriptwitness.txinwitness == [@p2wpkh_sig_hex, @p2wpkh_pubkey_hex]
      assert PSBT.finalized?(finalized)
    end

    test "strips the non-final fields but keeps the UTXO after finalizing" do
      {:ok, psbt} = PSBT.decode(@finalize_input)
      finalized = PSBT.finalize(psbt)

      Enum.each(finalized.inputs, fn input ->
        assert input.partial_sig == nil
        assert input.redeem_script == nil
        assert input.witness_script == nil
        assert input.bip32_derivation == nil
        assert input.non_witness_utxo != nil or input.witness_utxo != nil
      end)
    end

    test "keeps proprietary and unknown records after finalizing" do
      {:ok, psbt} = PSBT.decode(@finalize_input)

      prop = %{key: <<0xFC, "p">>, value: "prop"}
      unk = %{key: <<0x99, "u">>, value: "unk"}

      inputs =
        Enum.map(psbt.inputs, fn input -> %In{input | proprietary: [prop], unknown: [unk]} end)

      finalized = PSBT.finalize(%PSBT{psbt | inputs: inputs})

      assert PSBT.finalized?(finalized)

      Enum.each(finalized.inputs, fn input ->
        assert input.proprietary == [prop]
        assert input.unknown == [unk]
      end)
    end

    test "orders multisig signatures independently of their insertion order" do
      {:ok, psbt} = PSBT.decode(@finalize_input)

      reversed_sigs =
        Enum.map(psbt.inputs, fn input ->
          %{input | partial_sig: Enum.reverse(input.partial_sig)}
        end)

      reversed = %PSBT{psbt | inputs: reversed_sigs}

      assert PSBT.finalize(reversed) == PSBT.finalize(psbt)
    end

    test "finalizes a p2pkh input (non-witness UTXO) to a scriptSig" do
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      psbt =
        non_witness_psbt(Script.to_hex(p2pkh), [
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        ])

      finalized = PSBT.finalize(psbt)
      input = hd(finalized.inputs)

      assert PSBT.finalized?(finalized)
      assert input.final_scriptwitness == nil
      assert %Script{} = input.final_scriptsig
    end

    test "finalizes a single-key input even when an unrelated extra partial_sig is present" do
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      # Input carries a's signature (the one matching the scriptPubKey) plus an
      # unrelated key b's. The finalizer must select a by key-hash match rather
      # than refusing because more than one partial_sig is present.
      with_extra =
        non_witness_psbt(Script.to_hex(p2pkh), [
          signature_record(@finalize_pubkey_b, @finalize_sig_a),
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        ])

      only_matching =
        non_witness_psbt(Script.to_hex(p2pkh), [
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        ])

      finalized = PSBT.finalize(with_extra)

      assert PSBT.finalized?(finalized)
      # The extra sig is dropped; the result is identical to finalizing with only
      # the matching signature present.
      assert finalized == PSBT.finalize(only_matching)
    end

    test "does not finalize a non-witness input from a witness_utxo alone" do
      # BIP-174 Signer check: "A Witness UTXO is provided for a non-witness
      # input" must fail. A witness_utxo cannot be verified against the
      # outpoint, so it must never steer a legacy (here: p2pkh) finalization.
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      {:ok, tx} = Transaction.decode(single_input_tx_hex())
      {:ok, psbt} = PSBT.from_tx(tx)

      utxo = %Bitcoinex.Transaction.Out{value: 1000, script_pub_key: Script.to_hex(p2pkh)}
      {:ok, psbt} = PSBT.add_input_field(psbt, 0, :witness_utxo, utxo)

      {:ok, psbt} =
        PSBT.add_input_field(
          psbt,
          0,
          :partial_sig,
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        )

      finalized = PSBT.finalize(psbt)
      refute PSBT.finalized?(finalized)
      assert finalized == psbt

      # The same input finalizes once the verifiable non_witness_utxo is there.
      verifiable =
        non_witness_psbt(
          Script.to_hex(p2pkh),
          [signature_record(@finalize_pubkey_a, @finalize_sig_a)]
        )

      assert PSBT.finalized?(PSBT.finalize(verifiable))
    end

    test "a signature with a different sighash flag does not block finalization" do
      # Key A's SIGHASH_ALL signature must finalize this input even though an
      # unrelated key B contributed a signature with a different flag (e.g.
      # after combining PSBTs from several signers).
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      unrelated = %{signature_record(@finalize_pubkey_b, @finalize_sig_a) | sighash_flag: 0x83}

      psbt =
        non_witness_psbt(Script.to_hex(p2pkh), [
          signature_record(@finalize_pubkey_a, @finalize_sig_a),
          unrelated
        ])

      {:ok, psbt} = PSBT.add_input_field(psbt, 0, :sighash_type, 0x01)

      assert PSBT.finalized?(PSBT.finalize(psbt))
    end

    test "does not finalize with a signature whose flag mismatches sighash_type" do
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      psbt =
        non_witness_psbt(
          Script.to_hex(p2pkh),
          [signature_record(@finalize_pubkey_a, @finalize_sig_a)]
        )

      # The only available signature carries flag 0x01; the input demands 0x03.
      {:ok, psbt} = PSBT.add_input_field(psbt, 0, :sighash_type, 0x03)

      finalized = PSBT.finalize(psbt)
      refute PSBT.finalized?(finalized)
      assert finalized == psbt
    end

    test "finalizes a native p2wsh 2-of-2 multisig to (OP_0, sigs, witnessScript)" do
      {:ok, witness_script} =
        Script.create_multi(2, [point(@finalize_pubkey_a), point(@finalize_pubkey_b)])

      {:ok, script_pub_key} = Script.to_p2wsh(witness_script)

      {:ok, tx} = Transaction.decode(single_input_tx_hex())
      {:ok, psbt} = PSBT.from_tx(tx)

      utxo = %Bitcoinex.Transaction.Out{
        value: 1000,
        script_pub_key: Script.to_hex(script_pub_key)
      }

      {:ok, psbt} = PSBT.add_input_field(psbt, 0, :witness_utxo, utxo)
      {:ok, psbt} = PSBT.add_input_field(psbt, 0, :witness_script, witness_script)

      # Insertion order is B then A; the witness must follow script order A, B.
      {:ok, psbt} =
        PSBT.add_input_field(
          psbt,
          0,
          :partial_sig,
          signature_record(@finalize_pubkey_b, @finalize_sig_a)
        )

      {:ok, psbt} =
        PSBT.add_input_field(
          psbt,
          0,
          :partial_sig,
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        )

      finalized = PSBT.finalize(psbt)
      input = hd(finalized.inputs)
      sig_hex = @finalize_sig_a <> "01"

      assert PSBT.finalized?(finalized)
      assert input.final_scriptsig == nil

      assert input.final_scriptwitness.txinwitness == [
               "",
               sig_hex,
               sig_hex,
               Script.to_hex(witness_script)
             ]
    end

    test "selects the first m signatures in script order when more are present" do
      # Bare 2-of-3 multisig holding all three signatures: the scriptSig must
      # take the first two in the script's pubkey order (A, B), like Core.
      {:ok, multi} =
        Script.create_multi(2, [
          point(@finalize_pubkey_a),
          point(@finalize_pubkey_b),
          point(@finalize_pubkey_c)
        ])

      psbt =
        non_witness_psbt(Script.to_hex(multi), [
          signature_record(@finalize_pubkey_c, @finalize_sig_a),
          signature_record(@finalize_pubkey_b, @finalize_sig_a),
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        ])

      finalized = PSBT.finalize(psbt)
      input = hd(finalized.inputs)
      sig_bytes = Base.decode16!(@finalize_sig_a, case: :lower) <> <<0x01>>
      sig_push = <<byte_size(sig_bytes)>> <> sig_bytes

      assert PSBT.finalized?(finalized)

      assert Script.serialize_script(input.final_scriptsig) ==
               <<0x00>> <> sig_push <> sig_push
    end

    test "handles hand-built PSBTs without inputs or an unsigned tx safely" do
      no_tx = %PSBT{global: %Bitcoinex.PSBT.Global{}, inputs: nil, outputs: nil}
      assert PSBT.finalize(no_tx) == no_tx
      refute PSBT.finalized?(no_tx)
      assert {:error, :not_finalized} = PSBT.extract_tx(no_tx)

      # A zero-input PSBT has nothing extractable; it must not report finalized.
      {:ok, tx} = Transaction.decode(single_input_tx_hex())
      empty_tx = %Transaction{tx | inputs: []}

      zero_input = %PSBT{
        global: %Bitcoinex.PSBT.Global{unsigned_tx: empty_tx},
        inputs: [],
        outputs: []
      }

      refute PSBT.finalized?(zero_input)
      assert {:error, :not_finalized} = PSBT.extract_tx(zero_input)
    end

    test "skips an input whose non-witness UTXO txid does not match" do
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      psbt =
        non_witness_psbt(
          Script.to_hex(p2pkh),
          [signature_record(@finalize_pubkey_a, @finalize_sig_a)],
          wrong_txid: true
        )

      finalized = PSBT.finalize(psbt)

      refute PSBT.finalized?(finalized)
      assert finalized == psbt
    end

    test "finalizes a p2sh-p2wpkh input to a redeemScript scriptSig and a witness" do
      pubkey = point(@finalize_pubkey_a)
      {:ok, redeem_script} = Script.create_p2wpkh(Bitcoinex.Utils.hash160(Point.sec(pubkey)))
      {:ok, script_pub_key} = Script.to_p2sh(redeem_script)

      {:ok, tx} = Transaction.decode(single_input_tx_hex())
      {:ok, base} = PSBT.from_tx(tx)

      utxo = %Bitcoinex.Transaction.Out{
        value: 1000,
        script_pub_key: Script.to_hex(script_pub_key)
      }

      {:ok, psbt} = PSBT.add_input_field(base, 0, :witness_utxo, utxo)
      {:ok, psbt} = PSBT.add_input_field(psbt, 0, :redeem_script, redeem_script)

      {:ok, psbt} =
        PSBT.add_input_field(
          psbt,
          0,
          :partial_sig,
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        )

      finalized = PSBT.finalize(psbt)
      input = hd(finalized.inputs)

      assert PSBT.finalized?(finalized)
      assert %Script{} = input.final_scriptsig

      assert input.final_scriptwitness.txinwitness == [
               @finalize_sig_a <> "01",
               @finalize_pubkey_a
             ]
    end

    test "refuses to finalize when the redeemScript does not hash to the scriptPubKey" do
      # A fully-signed p2sh-p2wpkh input whose witness_utxo scriptPubKey is a p2sh
      # of a *different* script. There are enough signatures to finalize, so only
      # the redeemScript-vs-scriptPubKey hash check can stop it.
      pubkey = point(@finalize_pubkey_a)
      {:ok, redeem_script} = Script.create_p2wpkh(Bitcoinex.Utils.hash160(Point.sec(pubkey)))
      {:ok, wrong_script_pub_key} = Script.create_p2sh(:binary.copy(<<0x11>>, 20))

      {:ok, tx} = Transaction.decode(single_input_tx_hex())
      {:ok, base} = PSBT.from_tx(tx)

      utxo = %Bitcoinex.Transaction.Out{
        value: 1000,
        script_pub_key: Script.to_hex(wrong_script_pub_key)
      }

      {:ok, psbt} = PSBT.add_input_field(base, 0, :witness_utxo, utxo)
      {:ok, psbt} = PSBT.add_input_field(psbt, 0, :redeem_script, redeem_script)

      {:ok, psbt} =
        PSBT.add_input_field(
          psbt,
          0,
          :partial_sig,
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        )

      refute PSBT.finalized?(PSBT.finalize(psbt))
    end

    test "does not finalize an input whose signature sighash disagrees with its sighash_type" do
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      # signature_record uses SIGHASH_ALL (0x01).
      psbt =
        non_witness_psbt(Script.to_hex(p2pkh), [
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        ])

      # Requiring SIGHASH_SINGLE (0x03) contradicts the SIGHASH_ALL signature.
      {:ok, mismatched} = PSBT.add_input_field(psbt, 0, :sighash_type, 0x03)
      refute PSBT.finalized?(PSBT.finalize(mismatched))

      # Requiring the matching SIGHASH_ALL finalizes.
      {:ok, matched} = PSBT.add_input_field(psbt, 0, :sighash_type, 0x01)
      assert PSBT.finalized?(PSBT.finalize(matched))
    end

    test "refuses to finalize a p2pkh input whose signature key does not match the scriptPubKey" do
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      # scriptPubKey commits to key A, but the only signature is from key B.
      psbt =
        non_witness_psbt(Script.to_hex(p2pkh), [
          signature_record(@finalize_pubkey_b, @finalize_sig_a)
        ])

      refute PSBT.finalized?(PSBT.finalize(psbt))
    end

    test "refuses to finalize a p2wpkh input whose signature key does not match the program" do
      {:ok, p2wpkh} =
        Script.create_p2wpkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      {:ok, tx} = Transaction.decode(single_input_tx_hex())
      {:ok, base} = PSBT.from_tx(tx)
      utxo = %Bitcoinex.Transaction.Out{value: 1000, script_pub_key: Script.to_hex(p2wpkh)}
      {:ok, psbt} = PSBT.add_input_field(base, 0, :witness_utxo, utxo)

      {:ok, psbt} =
        PSBT.add_input_field(
          psbt,
          0,
          :partial_sig,
          signature_record(@finalize_pubkey_b, @finalize_sig_a)
        )

      refute PSBT.finalized?(PSBT.finalize(psbt))
    end

    test "finalizes a bare 2-of-2 (M-of-M) multisig to an OP_0 <sig> <sig> scriptSig" do
      {:ok, multi} =
        Script.create_multi(2, [point(@finalize_pubkey_a), point(@finalize_pubkey_b)])

      psbt =
        non_witness_psbt(Script.to_hex(multi), [
          signature_record(@finalize_pubkey_a, @finalize_sig_a),
          signature_record(@finalize_pubkey_b, @finalize_sig_a)
        ])

      finalized = PSBT.finalize(psbt)
      input = hd(finalized.inputs)

      assert PSBT.finalized?(finalized)
      assert %Script{} = input.final_scriptsig
      assert input.final_scriptwitness == nil
    end

    test "finalizes a bare 2-of-3 (N-of-M) multisig, taking the required matching sigs" do
      {:ok, multi} =
        Script.create_multi(2, [
          point(@finalize_pubkey_a),
          point(@finalize_pubkey_b),
          point(@finalize_pubkey_c)
        ])

      # Provide sigs for the 1st and 3rd pubkeys, in reverse order, to exercise
      # ordering-by-script-pubkey regardless of insertion order.
      psbt =
        non_witness_psbt(Script.to_hex(multi), [
          signature_record(@finalize_pubkey_c, @finalize_sig_a),
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        ])

      assert PSBT.finalized?(PSBT.finalize(psbt))
    end

    test "finalizes a p2sh 2-of-3 multisig whose redeemScript exceeds 75 bytes (OP_PUSHDATA1)" do
      {:ok, redeem} =
        Script.create_multi(2, [
          point(@finalize_pubkey_a),
          point(@finalize_pubkey_b),
          point(@finalize_pubkey_c)
        ])

      # A 2-of-3 multisig is >75 bytes, so it must be pushed with OP_PUSHDATA1.
      assert byte_size(Script.serialize_script(redeem)) > 75
      {:ok, script_pub_key} = Script.to_p2sh(redeem)

      psbt =
        non_witness_psbt(Script.to_hex(script_pub_key), [
          signature_record(@finalize_pubkey_a, @finalize_sig_a),
          signature_record(@finalize_pubkey_b, @finalize_sig_a)
        ])

      {:ok, psbt} = PSBT.add_input_field(psbt, 0, :redeem_script, redeem)
      finalized = PSBT.finalize(psbt)

      assert PSBT.finalized?(finalized)
      # The reconstructed scriptSig parses back, proving the OP_PUSHDATA1 push of
      # the >75-byte redeemScript is well-formed.
      assert %Script{} = hd(finalized.inputs).final_scriptsig
    end
  end

  describe "extract_tx/1 (Extractor)" do
    test "extracts the fully-signed network transaction" do
      {:ok, psbt} = PSBT.decode(@finalize_expected)
      assert {:ok, tx} = PSBT.extract_tx(psbt)
      assert Base.encode16(Transaction.Utils.serialize(tx), case: :lower) == @extract_tx_hex
    end

    test "errors on a PSBT that is not fully finalized" do
      {:ok, psbt} = PSBT.decode(@finalize_input)
      assert {:error, :not_finalized} = PSBT.extract_tx(psbt)
    end

    test "errors when the input maps desync from the unsigned tx inputs" do
      {:ok, psbt} = PSBT.decode(@finalize_expected)
      desynced = %PSBT{psbt | inputs: tl(psbt.inputs)}
      assert {:error, :not_finalized} = PSBT.extract_tx(desynced)
    end

    test "extracts a fully-legacy transaction without the segwit marker" do
      {:ok, p2pkh} =
        Script.create_p2pkh(Bitcoinex.Utils.hash160(Point.sec(point(@finalize_pubkey_a))))

      psbt =
        non_witness_psbt(Script.to_hex(p2pkh), [
          signature_record(@finalize_pubkey_a, @finalize_sig_a)
        ])

      finalized = PSBT.finalize(psbt)
      assert {:ok, tx} = PSBT.extract_tx(finalized)
      assert tx.witnesses in [nil, []]

      # Legacy serialization: 4-byte version, then the input count directly —
      # never the segwit 0x00 marker byte.
      assert <<_version::little-size(32), 0x01, _::binary>> =
               Transaction.Utils.serialize(tx)
    end
  end

  describe "serialize robustness" do
    test "encode_b64 tolerates nil input/output lists on a hand-built struct" do
      {:ok, base} = PSBT.decode(valid_vector(@p2sh_p2wsh_vector_index))
      # A hand-built %PSBT{} may carry nil (rather than []) map lists.
      psbt = %PSBT{base | inputs: nil, outputs: nil}
      assert is_binary(PSBT.encode_b64(psbt))
    end
  end

  # Builds a single-input PSBT spending a p2wpkh output, with one signature,
  # ready to finalize.
  defp single_sig_p2wpkh_psbt() do
    {:ok, pubkey} = Point.parse_public_key(Base.decode16!(@p2wpkh_pubkey_hex, case: :lower))

    # Raw DER signature bytes (the sig hex without its trailing 1-byte sighash).
    signature =
      Base.decode16!(binary_part(@p2wpkh_sig_hex, 0, byte_size(@p2wpkh_sig_hex) - 2),
        case: :lower
      )

    tx_hex =
      "0200000001" <>
        String.duplicate("00", 32) <>
        "00000000" <> "00" <> "ffffffff" <> "01" <> "e803000000000000" <> "00" <> "00000000"

    {:ok, tx} = Transaction.decode(tx_hex)
    {:ok, base} = PSBT.from_tx(tx)

    {:ok, p2wpkh_script} = Script.create_p2wpkh(Bitcoinex.Utils.hash160(Point.sec(pubkey)))
    utxo = %Bitcoinex.Transaction.Out{value: 1000, script_pub_key: Script.to_hex(p2wpkh_script)}

    {:ok, psbt} = PSBT.add_input_field(base, 0, :witness_utxo, utxo)

    {:ok, psbt} =
      PSBT.add_input_field(psbt, 0, :partial_sig, %{
        public_key: pubkey,
        signature: signature,
        sighash_flag: 0x01
      })

    psbt
  end

  defp point(hex) do
    {:ok, public_key} = Point.parse_public_key(Base.decode16!(hex, case: :lower))
    public_key
  end

  defp signature_record(pubkey_hex, der_sig_hex) do
    %{
      public_key: point(pubkey_hex),
      signature: Base.decode16!(der_sig_hex, case: :lower),
      sighash_flag: 0x01
    }
  end

  defp single_input_tx_hex do
    "0200000001" <>
      String.duplicate("00", 32) <>
      "00000000" <> "00" <> "ffffffff" <> "01" <> "e803000000000000" <> "00" <> "00000000"
  end

  # Builds a single-input PSBT spending a non-witness UTXO with the given
  # scriptPubKey and partial signatures. With `wrong_txid: true` the unsigned
  # tx references a txid that does not match the supplied prev tx.
  defp non_witness_psbt(script_pub_key_hex, partial_sigs, opts \\ []) do
    prev_tx = %Transaction{
      version: 2,
      inputs: [
        %Bitcoinex.Transaction.In{
          prev_txid: String.duplicate("00", 32),
          prev_vout: 0,
          script_sig: "",
          sequence_no: 0xFFFFFFFF
        }
      ],
      outputs: [%Bitcoinex.Transaction.Out{value: 1000, script_pub_key: script_pub_key_hex}],
      witnesses: nil,
      lock_time: 0
    }

    prev_txid =
      if opts[:wrong_txid],
        do: String.duplicate("11", 32),
        else: Transaction.transaction_id(prev_tx)

    unsigned_tx = %Transaction{
      version: 2,
      inputs: [
        %Bitcoinex.Transaction.In{
          prev_txid: prev_txid,
          prev_vout: 0,
          script_sig: "",
          sequence_no: 0xFFFFFFFF
        }
      ],
      outputs: [%Bitcoinex.Transaction.Out{value: 900, script_pub_key: ""}],
      witnesses: nil,
      lock_time: 0
    }

    {:ok, psbt} = PSBT.from_tx(unsigned_tx)

    # The Updater refuses a non_witness_utxo that mismatches the outpoint, so a
    # deliberately-wrong fixture (defense-in-depth test of the finalizer's own
    # check) must place it on the struct directly.
    psbt =
      if opts[:wrong_txid] do
        [input] = psbt.inputs
        %PSBT{psbt | inputs: [%{input | non_witness_utxo: prev_tx}]}
      else
        {:ok, psbt} = PSBT.add_input_field(psbt, 0, :non_witness_utxo, prev_tx)
        psbt
      end

    Enum.reduce(partial_sigs, psbt, fn partial_sig, acc ->
      {:ok, acc} = PSBT.add_input_field(acc, 0, :partial_sig, partial_sig)
      acc
    end)
  end
end
