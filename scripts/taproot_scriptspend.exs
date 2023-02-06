alias Bitcoinex.Secp256k1
alias Bitcoinex.Transaction
alias Bitcoinex.Script
alias Bitcoinex.Secp256k1
alias Bitcoinex.Secp256k1.{Point, PrivateKey, Signature, Schnorr}
alias Bitcoinex.Taproot

new_privkey = fn ->
  {:ok, sk} =
    32
    |> :crypto.strong_rand_bytes()
    |> :binary.decode_unsigned()
    |> PrivateKey.new()
  Secp256k1.force_even_y(sk)
end

# internal_key
internal_sk = new_privkey.()
internal_pk = PrivateKey.to_point(internal_sk)

# p2pk script key
p2pk_sk = new_privkey.()
p2pk_pk = PrivateKey.to_point(p2pk_sk)

{:ok, p2pk_script} = Script.create_p2pk(Point.x_bytes(p2pk_pk))

# single leaf
script_tree = Taproot.TapLeaf.from_script(Taproot.bip342_leaf_version(), p2pk_script)

{:ok, scriptpubkey} = Script.create_p2tr(internal_pk, script_tree)

{:ok, addr} = Script.to_address(scriptpubkey, :regtest)
# addr = bcrt1ptkdqw3d39fuzg9qtw6r6e2rj098tp5vffhhnyu8r7m62j00q3atq8hpx0m
# broadcast and mine funding tx
# EDIT note txid of funding tx
txid = "0492bc1dce2ee85c92533942219e1ca72069a395d2dc77d595bd2f171da4e6ce"
# EDIT to the vout of the output you created for the addr
vout = 0
# EDIT to the amount you sent in the UTXO above
amount = 100_000_000
# EDIT where you would like to spend to
dest_addr = "bcrt1pzeg29d38m506gtnunlg2tjh4hpvv4mtkjg5tku34ad24830pta5qg0kyn6"

{:ok, dest_script, _network} = Script.from_address(dest_addr)

tx = %Transaction{
  version: 1,
  inputs: [
    %Transaction.In{
      prev_txid: txid,
      prev_vout: vout,
      script_sig: "",
      sequence_no: 2147483648,
    }
  ],
  outputs: [
    %Transaction.Out{
      value: 50_000_000,
      script_pub_key: Script.to_hex(dest_script)
    }
  ],
  lock_time: 0
}

#sighash_default
hash_type = 0x00
ext_flag = 1
input_idx = 0

sighash = Transaction.bip341_sighash(
  tx,
  hash_type,
  ext_flag,
  input_idx,
  [amount],
  [Script.serialize_with_compact_size(scriptpubkey)],
  tapleaf: script_tree
)



aux_rand = 0
script_idx = 0

{:ok, sig} = Schnorr.sign(p2pk_sk, :binary.decode_unsigned(sighash), aux_rand)

control_block = Taproot.build_control_block(internal_pk, script_tree, script_idx)

hash_byte =
  if hash_type == 0x00 do
    <<>>
  else
    <<hash_type>>
  end

sig_hex = Signature.serialize_signature(sig) <> hash_byte |> Base.encode16(case: :lower)
script_hex = Script.to_hex(p2pk_script)
control_block_hex = control_block |> Base.encode16(case: :lower)

tx = %Transaction{tx | witnesses: [
  %Transaction.Witness{
    txinwitness: [sig_hex, script_hex, control_block_hex]
  }
]
}

Transaction.Utils.serialize(tx) |> Base.encode16(case: :lower)

# a97fb556cff86dda196cb2c9fa4892de259dc8b910ec72b60975822b88b05130
