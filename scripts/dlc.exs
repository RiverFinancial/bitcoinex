alias Bitcoinex.{Secp256k1,Transaction, Script, Utils, Taproot}
alias Bitcoinex.Secp256k1.{Point, PrivateKey, Signature, Schnorr}


new_rand_int = fn ->
  32
  |> :crypto.strong_rand_bytes()
  |> :binary.decode_unsigned()
end

new_privkey = fn ->
  {:ok, sk} =
    new_rand_int.()
    |> PrivateKey.new()
  Secp256k1.force_even_y(sk)
end

multisig_2_of_2_script = fn a, b ->
  # Script will be pseudo-multisig:
  # <BOB_PK> OP_CHECKSIGVERIFY <ALICE_PK> OP_CHECKSIG
  # Scripts are stacks, so must be inserted in reverse order.
  # This also means Alices Signature must come first in the witness_script
  s = Script.new()
  {:ok, s} = Script.push_op(s, :op_checksig)
  {:ok, s} = Script.push_data(s, Point.x_bytes(a))
  {:ok, s} = Script.push_op(s, :op_checksigverify)
  {:ok, s} = Script.push_data(s, Point.x_bytes(b))
  s
end

# Initial setup for this example: give Alice and bob one coin worth 100,010,000 sats each, in order to fund the DLC.
# these ouotputs will be simple keyspend-only P2TRs
alice_init_sk = new_privkey.()
alice_init_pk = PrivateKey.to_point(alice_init_sk)
alice_init_script_tree = nil
{:ok, alice_init_script} = Script.create_p2tr(alice_init_pk, alice_init_script_tree)
{:ok, alice_init_addr} = Script.to_address(alice_init_script, :regtest)

bob_init_sk = new_privkey.()
bob_init_pk = PrivateKey.to_point(bob_init_sk)
bob_init_script_tree = nil
{:ok, bob_init_script} = Script.create_p2tr(bob_init_pk, bob_init_script_tree)
{:ok, bob_init_addr} = Script.to_address(bob_init_script, :regtest)

# In your regtest node, send bitcoin to each of these 2 addresses in the amount 100_010_000.
# if you use a different amount, edit the *_init_amount variables below
# note the outpoints for both sends.
alice_init_txid = "57495e49895e87ac3ba2f2467abc6124df166a251a0e304eb770ccc040063af4"
alice_init_vout = 1
alice_init_amount = 100_010_000

bob_init_txid = "783bf305752377c006310d66756d680fa9e33c0e870d024b1c2269aa88f4654c"
bob_init_vout = 1
bob_init_amount = 100_010_000

### BEGIN DLC EXAMPLE ###

# First, Alice and Bob will create a 2-of-2 funding address

alice_fund_sk = new_privkey.()
alice_fund_pk = PrivateKey.to_point(alice_fund_sk)

bob_fund_sk = new_privkey.()
bob_fund_pk = PrivateKey.to_point(bob_fund_sk)

fund_script = multisig_2_of_2_script.(alice_fund_pk, bob_fund_pk)
# If you want to examine the script, uncomment next line:
# Script.display_script(fund_script)

fund_leaf = Taproot.TapLeaf.new(Taproot.bip342_leaf_version(), fund_script)

# WARNING: this address only has 1 spend option: a 2-of-2 multisig. Without additional timeout
# spendpaths (allowing both parties to recover funds if the other disappears), this is a trusted
# and unsafe contract to enter. TODO: add timeout allowing both parties to reclaim funds.

# P2TR for funding addr will have no internal key. Only way to spend is to satisfy the 2-of-2
# TODO: when MuSig is implemented, the KeySpend route can act as 2-of-2 instead, and is cheaper.
{:ok, fund_scriptpubkey, r} = Script.create_p2tr_script_only(fund_leaf, new_rand_int.())

# in the above, r is a random number used to create a unique but provably unspendable internal key
# in the case that we don't want a keypath spend to be possible. If either alice or bob generated the funding
# scriptpubkey, the other should verify that the internal key is unspendable and reconstruct the same script
# to ensure they know what contract they are sending their BTC to.
fund_p = Script.calculate_unsolvable_internal_key(r)
is_correct_p2tr = Script.validate_unsolvable_internal_key(fund_scriptpubkey, fund_leaf, r)

# ALICE NOR BOB should fund this address until both CETs are signed with adaptor sigs
{:ok, fund_addr} = Script.to_address(fund_scriptpubkey, :regtest)

# We create the funding transaction.
init_amounts = [alice_init_amount, bob_init_amount]
init_scriptpubkeys = [
  Script.serialize_with_compact_size(alice_init_script),
  Script.serialize_with_compact_size(bob_init_script)
]

fund_amount = 200_010_000
fund_tx = %Transaction{
  version: 1,
  inputs: [
    %Transaction.In{
      prev_txid: alice_init_txid,
      prev_vout: alice_init_vout,
      script_sig: "",
      sequence_no: 2147483648
    },
    %Transaction.In{
      prev_txid: bob_init_txid,
      prev_vout: bob_init_vout,
      script_sig: "",
      sequence_no: 2147483648
    }
  ],
  outputs: [
    %Transaction.Out{
      # fee of 10_000 sats paid for this tx. This means you'll probably have to disable max fee constraints in bitcoind to broadcast txs
      # the next 10_000 will go towards spending this output to settle the contract
      value: fund_amount,
      script_pub_key: Script.to_hex(fund_scriptpubkey)
    }
    # A more realistic example would have change outputs to each party here. Omitted for simplicity
  ],
  lock_time: 0
}

# even though the fund tx is not signed, we can calculate the txid and use that to create contract execution txs (CETs)
# which will spend the output created in this tx
fund_txid = Transaction.transaction_id(fund_tx)
# d4be73514a8535c6e21a6007b0de049ba3d4d7d93ee953852c4b7ce97369ff49
fund_vout = 0
fund_amounts = [fund_amount]
fund_scriptpubkeys = [Script.serialize_with_compact_size(fund_scriptpubkey)]

# Oracle Identity & Signing Key
oracle_sk = new_privkey.()
oracle_pk = PrivateKey.to_point(oracle_sk)

# Oracle creates 2 tweak/point pairs, one for each possible outcome
# The bet will be a simple MOON or CRASH bet.

# the same nonce must be used for both outcomes in order to guarantee that the Oracle
# cannot sign both events without leaking their own private key. In a more trust-minimized
# example, the Oracle should prove ownership of a UTXO with the public key they use for
# the signing, in order to prove that they have something at stake if they should sign both events.

# Oracle does not use the standard BIP340 method for generating a nonce.
# This is because the nonce must not commit to the message, so that it can
# be reused for either outcome.
oracle_event_nonce = new_privkey.()
event_nonce_point = PrivateKey.to_point(oracle_event_nonce)

moon_msg = "MOON! the price rose"
crash_msg = "CRASH! the price fell"

# Oracle Broadcasts its intention to sign one of the 2 events
public = %{
  oracle_pk: oracle_pk,
  event_nonce_point: event_nonce_point,
  case1: moon_msg,
  case2: crash_msg
  # note, arbitrary number of outcomes are workable here.
}

# Alice And Bob can now compute the Signature Point, which they will use as the tweak point for their adaptor signatures
moon_sighash = Utils.double_sha256(public.case1)
crash_sighash = Utils.double_sha256(public.case2)

moon_sig_point = Schnorr.calculate_signature_point(public.event_nonce_point, oracle_pk, moon_sighash)
crash_sig_point = Schnorr.calculate_signature_point(public.event_nonce_point, oracle_pk, crash_sighash)

# Alice and Bob create CETs (Settlement Transactions, which will spend the funding tx (not yet signed/broadcasted))

# Alice and Bob each need Addresses to settle to
# For simplicity, these dest addresses will be internal key only Taproot addresses
alice_dest_sk = new_privkey.()
alice_dest_pk = PrivateKey.to_point(alice_dest_sk)
{:ok, alice_dest_script} = Script.create_p2tr(alice_dest_pk, nil)
{:ok, alice_dest_addr} = Script.to_address(alice_dest_script, :regtest)

bob_dest_sk = new_privkey.()
bob_dest_pk = PrivateKey.to_point(bob_dest_sk)
{:ok, bob_dest_script} = Script.create_p2tr(bob_dest_pk, nil)
{:ok, bob_dest_addr} = Script.to_address(bob_dest_script, :regtest)

# CET hash type will be sighash default for both, for simplicity
cet_hash_type = 0x00

# First CET: MOON, alice wins, and gets 75% of the funding tx (excluding fees)
moon_cet = %Transaction{
  version: 1,
  inputs: [
    %Transaction.In{
      prev_txid: fund_txid,
      prev_vout: fund_vout,
      script_sig: "",
      sequence_no: 2147483648,
    }
  ],
  outputs: [
    # ALICE WINS! gets 150M sats from the 1M she put in
    %Transaction.Out{
      value: 150_000_000,
      script_pub_key: Script.to_hex(alice_dest_script)
    },
    # BOB LOSES :( gets 50M sats from the 1M he put in
    %Transaction.Out{
      value: 50_000_000,
      script_pub_key: Script.to_hex(bob_dest_script)
    }
  ],
  lock_time: 0
}
# calculate the sighash for the MOON CET
moon_cet_sighash = Transaction.bip341_sighash(
  moon_cet,
  cet_hash_type, # sighash_default (all)
  0x01, # we are using taproot scriptpath spend, so ext_flag must be 1
  0, # index we're going to sign
  fund_amounts, # list of amounts for each input being spent
  fund_scriptpubkeys, # list of prev scriptpubkeys for each input being spent
  tapleaf: fund_leaf
) |> :binary.decode_unsigned()

# Second CET: CRASH, bob wins, and gets 75% of the funding tx (excluding fees)
crash_cet = %Transaction{
  version: 1,
  inputs: [
    # Notice this input is the same coin spent in the Moon CET tx. So they can't both be valid.
    %Transaction.In{
      prev_txid: fund_txid,
      prev_vout: fund_vout,
      script_sig: "",
      sequence_no: 2147483648,
    }
  ],
  outputs: [
    # ALICE LOSES :( gets 50M sats from the 1M she put in
    %Transaction.Out{
      value: 50_000_000,
      script_pub_key: Script.to_hex(alice_dest_script)
    },
    # BOB WINS! gets 150M sats from the 1M he put in
    %Transaction.Out{
      value: 150_000_000,
      script_pub_key: Script.to_hex(bob_dest_script)
    }
  ],
  lock_time: 0
}
# calculate the Sighash for the CRASH CET
crash_cet_sighash = Transaction.bip341_sighash(
  crash_cet,
  cet_hash_type, # sighash_default (all)
  0x01, # we are using taproot scriptpath spend, so ext_flag = 1
  0, # only one input in this tx
  fund_amounts, # list of amounts for each input being spent
  fund_scriptpubkeys, # list of prev scriptpubkeys for each input being spent
  tapleaf: fund_leaf
) |> :binary.decode_unsigned()

# Alice and Bob now create adaptor signatures for each of these CETs. They must share both of their
# Adaptor Signatures with one another. These next 4 steps are in no particular order.

# Alice creates adaptor sig for Crash Case using crash_sig_point (tweak point/encryption key).
aux_rand = new_rand_int.() # generate some entropy for this signature
{:ok, alice_crash_adaptor_sig, alice_crash_was_negated} = Schnorr.encrypted_sign(alice_fund_sk, crash_cet_sighash, aux_rand, crash_sig_point)

# Bob creates adaptor sig for Moon Case using moon_sig_point (tweak point/encryption key).
aux_rand = new_rand_int.() # generate some entropy for this signature
{:ok, bob_moon_adaptor_sig, bob_moon_was_negated} = Schnorr.encrypted_sign(bob_fund_sk, moon_cet_sighash, aux_rand, moon_sig_point)

# Alice creates adaptor sig for Moon Case using moon_sig_point.
aux_rand = new_rand_int.() # generate some entropy for this signature
{:ok, alice_moon_adaptor_sig, alice_moon_was_negated} = Schnorr.encrypted_sign(alice_fund_sk, moon_cet_sighash, aux_rand, moon_sig_point)

# Bob creates adaptor sig for Crash Case using crash_sig_point.
aux_rand = new_rand_int.() # generate some entropy for this signature
{:ok, bob_crash_adaptor_sig, bob_crash_was_negated} = Schnorr.encrypted_sign(bob_fund_sk, crash_cet_sighash, aux_rand, crash_sig_point)

# Verification Time! Alice and Bob must each verify one another's adaptor signatures to ensure they will be
# valid once the Oracle publishes the resolution signature

# Bob verifies Alice's Crash signature
is_valid = Schnorr.verify_encrypted_signature(alice_crash_adaptor_sig, alice_fund_pk, crash_cet_sighash, crash_sig_point, alice_crash_was_negated)

# Alice verifies Bob's Moon signature
is_valid = Schnorr.verify_encrypted_signature(bob_moon_adaptor_sig, bob_fund_pk, moon_cet_sighash, moon_sig_point, bob_moon_was_negated)

# Bob verifies Alice's Moon signature
is_valid = Schnorr.verify_encrypted_signature(alice_moon_adaptor_sig, alice_fund_pk, moon_cet_sighash, moon_sig_point, alice_moon_was_negated)

# Alice verifies Bob's Crash signature
is_valid = Schnorr.verify_encrypted_signature(bob_crash_adaptor_sig, bob_fund_pk, crash_cet_sighash, crash_sig_point, bob_crash_was_negated)

# IFF all four adaptor signatures are valid, we're good to go!

# Now that each party has the other's adaptor signatures, they can sign and broadcast the
# Funding transaction (that was created way above). They could not previously do so safely,
# because if they had locked BTC in the 2-of-2 multisig before having their counterparty's
# Adaptor signatures, they could have lost those funds if the counterparty disappeared.
# NOTE: Again, the funding tx has no timeouts in place, so if the Oracle AND a counterparty disappear,
# those funds are locked irretreivably.

fund_hash_type = 0x00  # sighash_default (all)
fund_ext_flag = 0 # both parties are using keyspend
# This would be done independently by both parties, or collaboratively using PSBT,
alice_fund_sighash = Transaction.bip341_sighash(
  fund_tx,
  fund_hash_type,
  fund_ext_flag,
  0, # alice's input comes first
  init_amounts,
  init_scriptpubkeys
) |> :binary.decode_unsigned()

bob_fund_sighash = Transaction.bip341_sighash(
  fund_tx,
  fund_hash_type,
  fund_ext_flag,
  1, # bob's input comes second
  init_amounts,
  init_scriptpubkeys
) |> :binary.decode_unsigned()

# each party signs the funding transaction, moving their BTC into the 2-of-2 multisig.

# In order to sign the tx with the internal private key, they must first tweak it
# so that it can sign for the external taproot key
{_, alice_init_merkle_root_hash} = Taproot.merkelize_script_tree(alice_init_script_tree)
alice_q = Taproot.tweak_privkey(alice_init_sk, alice_init_merkle_root_hash)
aux_rand = new_rand_int.() # more entropy
{:ok, alice_fund_sig} = Schnorr.sign(alice_q, alice_fund_sighash, aux_rand)

{_, bob_init_merkle_root_hash} = Taproot.merkelize_script_tree(bob_init_script_tree)
aux_rand = new_rand_int.() # even more entropy
bob_q = Taproot.tweak_privkey(bob_init_sk, bob_init_merkle_root_hash)
{:ok, bob_fund_sig} = Schnorr.sign(bob_q, bob_fund_sighash, aux_rand)

fund_hash_byte =
  if fund_hash_type == 0x00 do
    <<>>
  else
    <<fund_hash_type>>
  end

alice_sig_hex = Signature.serialize_signature(alice_fund_sig) <> fund_hash_byte |> Base.encode16(case: :lower)
alice_witness = %Transaction.Witness{
  txinwitness: [
    alice_sig_hex
  ]
}

# NEXT: construct fund witness.
bob_sig_hex = Signature.serialize_signature(bob_fund_sig) <> fund_hash_byte |> Base.encode16(case: :lower)
bob_witness = %Transaction.Witness{
  txinwitness: [
    bob_sig_hex
  ]
}

fund_tx = %Transaction{fund_tx | witnesses: [
  alice_witness, bob_witness
]}

fund_tx_hex = Transaction.Utils.serialize(fund_tx) |> Base.encode16(case: :lower)
# 5ac6d378bdf1c55b08e92a03de343797b662cb953cd8f3bbfb7e0108bbba7841

# FUND TX IS READY TO BROADCAST!
# bitcoin-cli sendrawtransaction <fund_tx_hex> 0
# The 0 at the end disables max_fee constraints. Only do this if you're willing to pay a high fee.

# ...wait for oracle to announce result...

# RESOLUTION 1: MOON! Skip to RESOLUTION 2 to execute the CRASH scenario instead

# Oracle Publishes:
moon_sig = Schnorr.sign_with_nonce(oracle_sk, oracle_event_nonce, :binary.decode_unsigned(moon_sighash))

# Alice & Bob should make sure this is a valid Schnorr signature
is_valid = Schnorr.verify_signature(oracle_pk, :binary.decode_unsigned(moon_sighash), moon_sig)

# alice & bob can both now extract the moon_tweak, which is moon_sig.s and complete their moon_adaptor sigs.
# Since alice won, she has more incentive to do so
%Signature{s: settlement_secret} = moon_sig

{:ok, settlement_secret} = PrivateKey.new(settlement_secret)

cet_hash_byte =
  if cet_hash_type == 0x00 do
    <<>>
  else
    <<cet_hash_type>>
  end

# Then, Alice can decrypt Bob's signature
bob_moon_sig = Schnorr.decrypt_signature(bob_moon_adaptor_sig, settlement_secret, bob_moon_was_negated)
# why not verify?
is_valid = Schnorr.verify_signature(bob_fund_pk, moon_cet_sighash, bob_moon_sig)


# Alice can also decrypt her own adaptor signature
alice_moon_sig = Schnorr.decrypt_signature(alice_moon_adaptor_sig, settlement_secret, alice_moon_was_negated)
# Don't trust, verify
is_valid = Schnorr.verify_signature(alice_fund_pk, moon_cet_sighash, alice_moon_sig)

# fund_p is the internal taproot key. In this case, it is unsolvable, as verified earlier.
# we take fund_leaf, the script_tree from earlier, and select the index of the script we want to spend.
# Here, there is only 1 script in the tree, so idx must be 0
control_block = Taproot.build_control_block(fund_p, fund_leaf, 0)

# serialize everything for insertion into the tx
bob_moon_sig_hex = Signature.serialize_signature(bob_moon_sig) <> cet_hash_byte |> Base.encode16(case: :lower)
alice_moon_sig_hex = Signature.serialize_signature(alice_moon_sig) <> cet_hash_byte |> Base.encode16(case: :lower)
fund_script_hex = Script.to_hex(fund_script)
control_block_hex = control_block |> Base.encode16(case: :lower)


# She then adds these to the Moon CET and broadcasts it
tx = %Transaction{moon_cet | witnesses: [
  %Transaction.Witness{
    txinwitness: [bob_moon_sig_hex, alice_moon_sig_hex, fund_script_hex, control_block_hex]
  }
]
}

tx = %Transaction{moon_cet | witnesses: [
  %Transaction.Witness{
    txinwitness: [alice_moon_sig_hex, bob_moon_sig_hex, fund_script_hex, control_block_hex]
  }
]
}

Transaction.Utils.serialize(tx) |> Base.encode16(case: :lower)


# RESOLUTION 2: CRASH!
