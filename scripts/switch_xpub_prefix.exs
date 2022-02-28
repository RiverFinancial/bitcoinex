# script for converting an xpub to a tpub or similar transformation.
# Checksum will naturally change as well

xpub_str = "xpub..."

xpub_pfx = <<0x04, 0x88, 0xB2, 0x1E>>
xprv_pfx = <<0x04, 0x88, 0xAD, 0xE4>>
tpub_pfx = <<0x04, 0x35, 0x87, 0xCF>>
tprv_pfx = <<0x04, 0x35, 0x83, 0x94>>

# NOTE: DO NOT switch between pub and priv prefixes.
new_prefix = tpub_pfx


{:ok, xpub} = Bitcoinex.ExtendedKey.parse_extended_key(xpub_str)
xpub = %{xpub | prefix: new_prefix}
Bitcoinex.ExtendedKey.to_string(xpub)
# verify
# Bitcoinex.ExtendedKey.parse_extended_key(xpub)
