# script to generate P2WPKH addresses from an xpub
# set the constants and then run script to write
# a CSV file of format: path, script, address
# to the output_file

change = 0 # set 0 for recv addresses, 1 for change addresses
network = :regtest # :testnet or :regtest
start_idx = 0
end_idx = 20
xpub_str = "xpub..."
output_file = "addresses.txt"

{:ok, file} = File.open(output_file, [:write])
{:ok, xpub} = Bitcoinex.ExtendedKey.parse_extended_key(xpub_str)
for i <- start_idx..end_idx do
	{:ok, xkey} = Bitcoinex.ExtendedKey.derive_extended_key(xpub, %Bitcoinex.ExtendedKey.DerivationPath{child_nums: [change,i]})
	{:ok, pub} = Bitcoinex.ExtendedKey.to_public_key(xkey)
	{:ok, s} = Bitcoinex.Script.public_key_to_p2wpkh(pub)
	{:ok, addr} = Bitcoinex.Script.to_address(s, network)
	# write path
	IO.binwrite(file, "#{change}/#{i}")
	IO.binwrite(file, ", ")
	# write scriptpubkey (hex)
	IO.binwrite(file, Bitcoinex.Script.to_hex(s))
	IO.binwrite(file, ", ")
	# write addr
	IO.binwrite(file, addr)
	IO.binwrite(file, "\n")
end
File.close(file)
