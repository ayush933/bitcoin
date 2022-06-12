#!/usr/bin/env python3
# Copyright (c) 2016-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test NULLDUMMY softfork.

Connect to a single node.
Generate 2 blocks (save the coinbases for later).
Generate COINBASE_MATURITY (CB) more blocks to ensure the coinbases are mature.
[Policy/Consensus] Check that NULLDUMMY compliant transactions are accepted in block CB + 3.
[Policy] Check that non-NULLDUMMY transactions are rejected before activation.
[Consensus] Check that the new NULLDUMMY rules are not enforced on block CB + 4.
[Policy/Consensus] Check that the new NULLDUMMY rules are enforced on block CB + 5.
"""
import time
from test_framework.script_util import script_to_p2wsh_script,script_to_p2sh_p2wsh_script,key_to_p2sh_p2wpkh_script
from test_framework.key import ECKey

from test_framework.blocktools import (
    COINBASE_MATURITY,
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
    create_transaction,
)
from test_framework.messages import CTransaction, tx_from_hex
from test_framework.script import (
    OP_0,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
    getnewdestination,
)
from test_framework.address import byte_to_base58,script_to_p2sh

NULLDUMMY_ERROR = "non-mandatory-script-verify-flag (Dummy CHECKMULTISIG argument must be zero)"


def invalidate_nulldummy_tx(tx):
    """Transform a NULLDUMMY compliant tx (i.e. scriptSig starts with OP_0)
    to be non-NULLDUMMY compliant by replacing the dummy with OP_TRUE"""
    assert_equal(tx.vin[0].scriptSig[0], OP_0)
    tx.vin[0].scriptSig = bytes([OP_TRUE]) + tx.vin[0].scriptSig[1:]
    tx.rehash()


class NULLDUMMYTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # This script tests NULLDUMMY activation, which is part of the 'segwit' deployment, so we go through
        # normal segwit activation here (and don't use the default always-on behaviour).
        self.extra_args = [[
            f'-testactivationheight=segwit@{COINBASE_MATURITY + 5}',
            '-addresstype=legacy',
            '-par=1',  # Use only one script thread to get the exact reject reason for testing
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.wallet = MiniWallet(test_node=self.nodes[0],mode=MiniWalletMode.RAW_P2PK)
        self.nodes[0].createwallet(wallet_name='wmulti', disable_private_keys=True)
        wmulti = self.nodes[0].get_wallet_rpc('wmulti')
        w0 = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.address = getnewdestination()[2]
        self.priv_key = ECKey()
        self.priv_key.generate()
        self.pubkey = self.priv_key.get_pubkey().get_bytes().hex()
        cms = self.nodes[0].createmultisig(1,[self.pubkey])
        self.ms_address = cms["address"]
        self.rs = cms["redeemScript"]
        # self.wit_address = w0.getnewaddress(address_type='p2sh-segwit')
        self.wit_address = getnewdestination(address_type='p2sh-segwit')[2]
        print(self.wit_address)
        # self.wit_ms_address = wmulti.addmultisigaddress(1, [self.pubkey], '', 'p2sh-segwit')['address']
        wms = self.nodes[0].createmultisig(1,[self.pubkey],'p2sh-segwit')
        print(wms)
        self.wrs = wms["redeemScript"]
        self.wit_ms_address = wms['address']
        print(self.nodes[0].validateaddress(self.wit_ms_address),"\n----")
        if not self.options.descriptors:
            # Legacy wallets need to import these so that they are watched by the wallet. This is unnecessary (and does not need to be tested) for descriptor wallets
            wmulti.importaddress(self.ms_address)
            wmulti.importaddress(self.wit_ms_address)

        self.coinbase_blocks = self.generate(self.nodes[0], 2)  # block height = 2
        coinbase_txid = []
        for i in self.coinbase_blocks:
            coinbase_txid.append(self.nodes[0].getblock(i)['tx'][0])
        self.generate(self.nodes[0], COINBASE_MATURITY)  # block height = COINBASE_MATURITY + 2
        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.lastblockheight = COINBASE_MATURITY + 2
        self.lastblocktime = int(time.time()) + self.lastblockheight

        self.log.info(f"Test 1: NULLDUMMY compliant base transactions should be accepted to mempool and mined before activation [{COINBASE_MATURITY + 3}]")
        inputs = [{"txid": coinbase_txid[0], "vout" : 0 }]
        outputs = {self.ms_address : 49}
        rawtx = self.nodes[0].createrawtransaction(inputs,outputs)
        signedtx = self.nodes[0].signrawtransactionwithkey(hexstring=rawtx, privkeys=[self.nodes[0].PRIV_KEYS[0][1]])
        # print(signedtx,"\n-----")
        test1txs = [tx_from_hex(signedtx["hex"])]
        txid1 = self.nodes[0].sendrawtransaction(test1txs[0].serialize_with_witness().hex(), 0)

        self.spk = test1txs[0].vout[0].scriptPubKey.hex()
        inputs = [{"txid": txid1, "vout" : 0}]#, "scriptPubKey": self.spk, "redeemScript": self.rs}]
        outputs = {self.ms_address : 48}
        rawtx = self.nodes[0].createrawtransaction(inputs,outputs)
        pk = byte_to_base58(self.priv_key.get_bytes()+b'\x01',239)
        signedtx = self.nodes[0].signrawtransactionwithkey(rawtx, [pk],[{"txid": txid1, "vout" : 0, "scriptPubKey": self.spk, "redeemScript": self.rs}])
        test1txs.append(tx_from_hex(signedtx["hex"]))
        txid2 = self.nodes[0].sendrawtransaction(test1txs[1].serialize_with_witness().hex(), 0)
        inputs = [{"txid": coinbase_txid[1], "vout" : 0}]
        outputs = {self.wit_ms_address : 49}
        rawtx = self.nodes[0].createrawtransaction(inputs,outputs)
        signedtx = self.nodes[0].signrawtransactionwithkey(hexstring=rawtx, privkeys=[self.nodes[0].PRIV_KEYS[0][1]])
        print(signedtx)
        test1txs.append(tx_from_hex(signedtx["hex"]))
        print(test1txs[-1])
        # test1txs.append(create_transaction(self.nodes[0], coinbase_txid[1], self.wit_ms_address, amount=49))
        txid3 = self.nodes[0].sendrawtransaction(test1txs[2].serialize_with_witness().hex(), 0)
        self.wspk = test1txs[-1].vout[0].scriptPubKey.hex()
        self.block_submit(self.nodes[0], test1txs, accept=True)

        self.log.info("Test 2: Non-NULLDUMMY base multisig transaction should not be accepted to mempool before activation")
        inputs = [{"txid": txid2, "vout" : 0}]#, "scriptPubKey": self.spk, "redeemScript": self.rs}]
        outputs = {self.ms_address : 47}
        rawtx = self.nodes[0].createrawtransaction(inputs,outputs)
        signedtx = self.nodes[0].signrawtransactionwithkey(rawtx, [pk],[{"txid": txid2, "vout" : 0, "scriptPubKey": self.spk, "redeemScript": self.rs}])
        test2tx = tx_from_hex(signedtx["hex"])
        # test2tx = create_transaction(self.nodes[0], txid2, self.ms_address, amount=47)
        invalidate_nulldummy_tx(test2tx)
        assert_raises_rpc_error(-26, NULLDUMMY_ERROR, self.nodes[0].sendrawtransaction, test2tx.serialize_with_witness().hex(), 0)

        self.log.info(f"Test 3: Non-NULLDUMMY base transactions should be accepted in a block before activation [{COINBASE_MATURITY + 4}]")
        self.block_submit(self.nodes[0], [test2tx], accept=True)

        self.log.info("Test 4: Non-NULLDUMMY base multisig transaction is invalid after activation")
        inputs = [{"txid": test2tx.hash, "vout" : 0}]#, "scriptPubKey": self.spk, "redeemScript": self.rs}]
        outputs = {self.address : 46}
        rawtx = self.nodes[0].createrawtransaction(inputs,outputs)
        signedtx = self.nodes[0].signrawtransactionwithkey(rawtx, [pk],[{"txid": txid2, "vout" : 0, "scriptPubKey": self.spk, "redeemScript": self.rs}])
        test4tx = tx_from_hex(signedtx["hex"])
        # test4tx = create_transaction(self.nodes[0], test2tx.hash, self.address, amount=46)
        test6txs = [CTransaction(test4tx)]
        invalidate_nulldummy_tx(test4tx)
        assert_raises_rpc_error(-26, NULLDUMMY_ERROR, self.nodes[0].sendrawtransaction, test4tx.serialize_with_witness().hex(), 0)
        self.block_submit(self.nodes[0], [test4tx], accept=False)

        self.log.info("Test 5: Non-NULLDUMMY P2WSH multisig transaction invalid after activation")
        input = {"txid": txid3, "vout" : 0,  "scriptPubKey": self.wspk}
        input["witnessScript"] = self.wrs
        input["redeemScript"] = script_to_p2wsh_script(self.wrs).hex()
        outputs = {self.wit_address : 48}
        rawtx = self.nodes[0].createrawtransaction([input],outputs)
        signedtx = self.nodes[0].signrawtransactionwithkey(rawtx, [pk],[input])
        test5tx = tx_from_hex(signedtx["hex"])
        print(signedtx)
        # test5tx = create_transaction(self.nodes[0], txid3, self.wit_address, amount=48)
        test6txs.append(CTransaction(test5tx))
        test5tx.wit.vtxinwit[0].scriptWitness.stack[0] = b'\x01'
        assert_raises_rpc_error(-26, NULLDUMMY_ERROR, self.nodes[0].sendrawtransaction, test5tx.serialize_with_witness().hex(), 0)
        self.block_submit(self.nodes[0], [test5tx], with_witness=True, accept=False)

        self.log.info(f"Test 6: NULLDUMMY compliant base/witness transactions should be accepted to mempool and in block after activation [{COINBASE_MATURITY + 5}]")
        for i in test6txs:
            self.nodes[0].sendrawtransaction(i.serialize_with_witness().hex(), 0)
        self.block_submit(self.nodes[0], test6txs, with_witness=True, accept=True)

    def block_submit(self, node, txs, *, with_witness=False, accept):
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(tmpl['previousblockhash'], self.lastblockhash)
        assert_equal(tmpl['height'], self.lastblockheight + 1)
        block = create_block(tmpl=tmpl, ntime=self.lastblocktime + 1, txlist=txs)
        if with_witness:
            add_witness_commitment(block)
        block.solve()
        assert_equal(None if accept else NULLDUMMY_ERROR, node.submitblock(block.serialize().hex()))
        if accept:
            assert_equal(node.getbestblockhash(), block.hash)
            self.lastblockhash = block.hash
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert_equal(node.getbestblockhash(), self.lastblockhash)


if __name__ == '__main__':
    NULLDUMMYTest().main()
