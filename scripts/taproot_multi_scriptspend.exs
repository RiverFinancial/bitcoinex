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

# p2pk script key 1
p2pk1_sk = new_privkey.()
p2pk1_pk = PrivateKey.to_point(p2pk1_sk)

{:ok, p2pk1_script} = Script.create_p2pk(Point.x_bytes(p2pk1_pk))

# p2pk script key 2
p2pk2_sk = new_privkey.()
p2pk2_pk = PrivateKey.to_point(p2pk2_sk)

{:ok, p2pk2_script} = Script.create_p2pk(Point.x_bytes(p2pk2_pk))


leaf0 = Taproot.TapLeaf.from_script(Taproot.bip342_leaf_version(), p2pk1_script)

leaf1 = Taproot.TapLeaf.from_script(Taproot.bip342_leaf_version(), p2pk2_script)

# single leaf
script_tree = {leaf0, leaf1}

{:ok, scriptpubkey} = Script.create_p2tr(internal_pk, script_tree)

{:ok, addr} = Script.to_address(scriptpubkey, :regtest)
# addr = bcrt1pwfprzzadfx3meyn5glm0rfmyl6lgmelqgwfqvxwx3hr756tcr77spqf2aq
# broadcast and mine funding tx
# EDIT note txid of funding tx
txid = "f11bfaa48121c582f652f0a1643c7b5a1692fe3582dff7819d2787486e595f68"
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

# here is where you choose which leaf to use. script_idx must match leaf #
script_idx = 0
leaf = leaf0
sk = p2pk1_sk
script = p2pk1_script

sighash = Transaction.bip341_sighash(
  tx,
  hash_type,
  ext_flag,
  input_idx,
  [amount],
  [Script.serialize_with_compact_size(scriptpubkey)],
  tapleaf: leaf
)

aux_rand = 0

{:ok, sig} = Schnorr.sign(sk, :binary.decode_unsigned(sighash), aux_rand)

control_block = Taproot.build_control_block(internal_pk, script_tree, script_idx)

hash_byte =
  if hash_type == 0x00 do
    <<>>
  else
    <<hash_type>>
  end

sig_hex = Signature.serialize_signature(sig) <> hash_byte |> Base.encode16(case: :lower)
script_hex = Script.to_hex(script)
control_block_hex = control_block |> Base.encode16(case: :lower)

tx = %Transaction{tx | witnesses: [
  %Transaction.Witness{
    txinwitness: [sig_hex, script_hex, control_block_hex]
  }
]
}

Transaction.Utils.serialize(tx) |> Base.encode16(case: :lower)

# 01000000000101685f596e4887279d81f7df8235fe92165a7b3c64a1f052f682c52181a4fa1bf10000000000000000800180f0fa02000000002251201650a2b627dd1fa42e7c9fd0a5caf5b858caed769228bb7235eb5553c5e15f680340f53ea81564380d49cd2bdf4bee89b5784a846048818cda51c284c6fd8eaf542bd3d25df4d696c5063d016b8fcab85e2eb78503bca277783a721a2c053c7266972220f6c4e1e4276a75cfcbba374608887f64e09a55a9e6166fe4856324d084c4a784ac41c1a280169a8ed09e3c4b34f832c0ae44d78bb081631c00084f12a602218734a27d9d06d23f4e9ac0a6d9eb2923d59c40b113cb3a150062410da36bc7408584faee00000000

# ALTERNATE script
script_idx = 1
leaf = leaf1
sk = p2pk2_sk
script = p2pk2_script

sighash = Transaction.bip341_sighash(
  tx,
  hash_type,
  ext_flag,
  input_idx,
  [amount],
  [Script.serialize_with_compact_size(scriptpubkey)],
  tapleaf: leaf
)

aux_rand = 0

{:ok, sig} = Schnorr.sign(sk, :binary.decode_unsigned(sighash), aux_rand)

control_block = Taproot.build_control_block(internal_pk, script_tree, script_idx)

hash_byte =
  if hash_type == 0x00 do
    <<>>
  else
    <<hash_type>>
  end

sig_hex = Signature.serialize_signature(sig) <> hash_byte |> Base.encode16(case: :lower)
script_hex = Script.to_hex(script)
control_block_hex = control_block |> Base.encode16(case: :lower)

tx = %Transaction{tx | witnesses: [
  %Transaction.Witness{
    txinwitness: [sig_hex, script_hex, control_block_hex]
  }
]
}

Transaction.Utils.serialize(tx) |> Base.encode16(case: :lower)


# a97fb556cff86dda196cb2c9fa4892de259dc8b910ec72b60975822b88b05130
