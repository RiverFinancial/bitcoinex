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

sk = new_privkey.()
pk = PrivateKey.to_point(sk)

# EDIT if you want to include a script tree (optional, but spending is not yet enabled)
script_tree = nil

{:ok, scriptpubkey} = Script.create_p2tr(pk, script_tree)

{:ok, addr} = Script.to_address(scriptpubkey, :regtest)
# EDIT to the unique addr
# addr = "bcrt1pfh4qvlzrgmf6f8e6urjkf3ax83kz02xqc8zujnpeycxgc3wrqmxs8py692"
# EDIT to the txid of your send to the addr above
txid = "bcdf4b0088a75c139d0b4858164534585b735dcdd18321824a31936abcbf04b4"
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
ext_flag = 0
input_idx = 0

sighash = Transaction.bip341_sighash(
  tx,
  hash_type,
  ext_flag,
  input_idx,
  [amount],
  [Script.serialize_with_compact_size(scriptpubkey)]
)

{_, merkle_root_hash} = Taproot.merkelize_script_tree(script_tree)

q_sk = Taproot.tweak_privkey(sk, merkle_root_hash)

{:ok, sig} = Schnorr.sign(q_sk, :binary.decode_unsigned(sighash), 0)

hash_byte =
  if hash_type == 0x00 do
    <<>>
  else
    <<hash_type>>
  end

witness_script = Signature.serialize_signature(sig) <> hash_byte |> Base.encode16(case: :lower)

tx = %Transaction{tx | witnesses: [
  %Transaction.Witness{
    txinwitness: [
      witness_script
    ]
  }
]
}

Transaction.Utils.serialize(tx)

# the last zero arg is to disable max_fee_rate
# use bitcoin-cli sendrawtransaction <tx_hex> 0
# txid: 86dcdf6a88480a16524aa353b47d11228d67f96f59c4a645d65d4aac09330065
