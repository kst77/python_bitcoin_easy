import hashlib
import struct
import binascii
import base58
from  utils_bitcoin import getwsdata
from  utils_bitcoin import getDataForMining
import time
from datetime import datetime
import calendar


class Miner():
    def __init__(self, receiver_address, message):
        self.receiver_address = receiver_address
        self.message = message


    def makeCoinBaseTransaction(self, script, receiver_address, value, height_block):

        source_transaction = "0000000000000000000000000000000000000000000000000000000000000000"
        source_output_index = 4294967295  #0xFFFFFFFF
        receiver_hashed_pubkey = binascii.hexlify(base58.b58decode_check(receiver_address)[1:])

        version = struct.pack("<L", 1)
        lock_time = struct.pack("<L", 0)

        tx_in_count = struct.pack("<B", 1)


        tx_in = {}

        tx_in["outpoint_hash"]  = binascii.unhexlify(source_transaction)[::-1]
        tx_in["outpoint_index"] = struct.pack("<L", source_output_index)

        height = struct.pack("<L", height_block)
        if height[-1] == 0:
            height = height[:-1]

        height = struct.pack("<B", (len(height))) + height


        tx_in["script"]         = height + script
        tx_in["script_length"]  = struct.pack("<B", (len(tx_in["script"])))
        tx_in["sequence"]       = binascii.unhexlify("ffffffff")

        tx_out_count = struct.pack("<B", 1)

        tx_out = {}
        tx_out["value"] = struct.pack("<Q", value)
        tx_out["pk_script"] = binascii.unhexlify(bytes('76a914', 'utf-8') + receiver_hashed_pubkey +  bytes('88ac', 'utf-8'))
        tx_out["pk_script_length"] = struct.pack("<B", (len(tx_out["pk_script"])))


        tx_to_sign = (version + tx_in_count +
                     tx_in["outpoint_hash"] + tx_in["outpoint_index"] + tx_in["script_length"]  + tx_in["script"] + tx_in["sequence"] +
                     tx_out_count + tx_out["value"] + tx_out["pk_script_length"] + tx_out["pk_script"] + lock_time)



        return tx_to_sign



    def merkle(self, hashList):
        # Hash pairs of items recursively until a single value is obtained
        if len(hashList) == 1:
            return hashList[0]
        newHashList = []
        # Process pairs. For odd length, the last is skipped
        for i in range(0, len(hashList)-1, 2):
            newHashList.append(self.hash2(hashList[i], hashList[i+1]))
        if len(hashList) % 2 == 1: # odd, hash last item twice
            newHashList.append(self.hash2(hashList[-1], hashList[-1]))
        return self.merkle(newHashList)

    def hash2(self, a, b):
        # Reverse inputs before and after hashing
        # due to big-endian / little-endian nonsense
        a1 = binascii.unhexlify(a)[::-1]
        b1 = binascii.unhexlify(b)[::-1]
        h = hashlib.sha256(hashlib.sha256(a1+b1).digest()).digest()
        return binascii.hexlify(h[::-1])

    def getTxnHash(self, txn):
        return binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify(txn)).digest()).digest())[::1].decode('ascii')

    def getMerkel(self, txn_pool):
        txn_hashes = list(map(self.getTxnHash, txn_pool))
        return self.merkle(txn_hashes)




    def getDataForMining(self, tranCount):
        wsdata = getwsdata('utx', tranCount)

        fee_total = 0

        tx_pool = []

        for wsdataitem in wsdata:
            hash = wsdataitem['x']['hash']
            inp_value = 0
            out_value = 0
            for inp in wsdataitem['x']['inputs']:
                inp_value += inp['prev_out']['value']

            for out in wsdataitem['x']['out']:
                out_value += out['value']

            fee_value = inp_value - out_value

            if fee_value < 0:
                continue

            fee_total += fee_value


            fp = urllib.request.urlopen("https://blockchain.info/tx/"+hash+"?format=hex")
            txhex = fp.read()
            fp.close()
            tx_pool.append(txhex)

        wsdata = getwsdata('block', 1)

        last_block = next(wsdata)['x']


        prev_block_hash = last_block['hash']
        height_new_block = last_block['height'] + 1

        start_block_reward = 50*100000000
        reward_interval = 210000

        pow = height_new_block//reward_interval


        current_reward = start_block_reward
        while pow > 0:
            current_reward /=2
            pow -=1


        value_coinbase_tx = int(current_reward + fee_total)


        bits = last_block['bits']
        exp  = int(hex(bits)[2:4], 16)
        mant = int(hex(bits)[4:10], 16)
        target = mant * (2 ** (8 * (exp - 3)))    # recalculate every 2016 block

        return prev_block_hash, tx_pool, bits, target, value_coinbase_tx, height_new_block


    def start(self):
        script = bytes("Mined by ME", 'utf-8')

        nonce = 0
        ver_block = 2

        prev_block_hash, txn_pool, bits, target, value_coinbase_tx, height_new_block = getDataForMining(4)
        target_bytes = binascii.unhexlify('%064x' % target)

        difficulty = int('00000000ffff0000000000000000000000000000000000000000000000000000', 16) / target

        txn_coinbase = self.makeCoinBaseTransaction(script, self.receiver_address, value_coinbase_tx, height_new_block)
        txnHex_coinbase = binascii.hexlify(txn_coinbase)
        txn_pool.insert(0, txnHex_coinbase)

        merkle_root = self.getMerkel(txn_pool)
        d = datetime.utcnow()
        unixtime = calendar.timegm(d.utctimetuple())

        cnt = 0
        isInit = False
        start_time = time.time()
        # https://bitcoinwisdom.com/bitcoin/difficulty
        while nonce < 0x100000000:

            header = (struct.pack("<L", ver_block) + binascii.unhexlify(prev_block_hash)[::-1] +
                      binascii.unhexlify(merkle_root)[::-1] + struct.pack("<LLL", unixtime, bits, nonce))

            hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()

            if isInit == False:
                cnt += 1
                if cnt % 1000:
                    if time.time() - start_time > 1:
                        isInit = True

                        sec = int((2 ** 32) * difficulty / cnt)
                        year = sec / (60 * 60 * 24 * 365)
                        print(
                            'Miner is in process. Current hash rate %s per second. Average time to mine one block with this hardware is %s years. Good Luck!' % (
                            cnt, year))

            if hash[::-1] < target_bytes:
                print('Found!!')
                break

            nonce += 1


if __name__ == '__main__':
    miner = Miner('1FGGdEdNtHiQwKnq9YdPPuLU18EA1JoKSC','Mined by me')
    miner.start()




