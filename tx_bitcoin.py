import struct
import hashlib
import binascii
import base58
import ecdsa
import utils_bitcoin

def makeRowTransaction(prev_outputs, scripts, receivers):
    # Protocol description of tx is here https://en.bitcoin.it/wiki/Protocol_documentation#tx

    version = struct.pack("<L", 1)      #Version
    tx_in_count = struct.pack("<B", len(prev_outputs))  # Number of Transaction inputs

    tx_in = bytes()
    for outpoint_hash, outpoint_index in prev_outputs.items():

        tx_in_current =  (binascii.unhexlify(outpoint_hash)[::-1] +  #	hash
                          struct.pack("<L", outpoint_index))


        tx_in_current += struct.pack("<B", (len(scripts[outpoint_hash]))) + scripts[outpoint_hash]
        tx_in_current += binascii.unhexlify("ffffffff")
        tx_in += tx_in_current


    tx_out_count = struct.pack("<B", len(receivers))

    tx_out = bytes()
    for addrr, value in receivers.items():
        receiver_hashed_pubkey = binascii.hexlify(base58.b58decode_check(addrr)[1:])

        # Locking Script(scriptPubKey)
        # ScriptPubKey = OP_DUP OP_HASH160 <hash160(pubKey)> OP_EQUAL OP_CHECKSIG
        # 0x76 = OP_DUP
        # 0xa9 = OP_HASH160
        # 0x14 = indication that 14 bytes of indormation follow
        # 0x88 = OP_EQUAL
        # 0xac = OP_CHECKSIG

        pk_script = binascii.unhexlify(bytes('76a914', 'utf-8') + receiver_hashed_pubkey +  bytes('88ac', 'utf-8')) # TxOut pk_script

        pk_script_len = struct.pack("<B", (len(pk_script)))  # TxOut pk_script  length

        tx_out_current = struct.pack("<Q", value) + pk_script_len + pk_script
        tx_out +=  tx_out_current


    lock_time = struct.pack("<L", 0)  # Lock_time

    tx_to_sign = (version +
                  tx_in_count + tx_in +
                  tx_out_count + tx_out +
                  lock_time)


    return tx_to_sign


def makeSignTransaction(prev_outputs, private_key, my_address, receivers):

    def intToHex(d):
        h = "%x" % d
        if len(h) % 2 == 1:
            h = '0' + h
        return h

    my_hashed_pubkey = binascii.hexlify(base58.b58decode_check(my_address)[1:])

    # Here is a temporery script, it's needed to sign transaction
    scriptrow = binascii.unhexlify(bytes('76a914', 'utf-8') + my_hashed_pubkey +  bytes('88ac', 'utf-8'))
    hash_code = struct.pack("<L", 1)

    sk = ecdsa.SigningKey.from_string(binascii.unhexlify(private_key), curve=ecdsa.SECP256k1)

    sigscripts = dict()

    for outpoint_hash, outpoint_index in prev_outputs.items():
        scripts = dict()

        # When you have more than 1 input, you have to remove others scripts to get signed script
        for outpoint_hash_inner, outpoint_index_inner in prev_outputs.items():
            if outpoint_hash_inner == outpoint_hash:
                scripts[outpoint_hash_inner] = scriptrow
            else:
                scripts[outpoint_hash_inner] = bytes()


        tx_to_sign = makeRowTransaction(prev_outputs, scripts, receivers) + hash_code
        hashed_raw_tx = hashlib.sha256(hashlib.sha256(tx_to_sign).digest()).digest()

        # Signing raw script with private key

        sign_bytes =  sk.sign_digest(hashed_raw_tx, sigencode=ecdsa.util.sigencode_der)

        # The signature is composed of two values, the r value and the s value.  if s value is greater than N/2 then s = N - s.
        N = 115792089237316195423570985008687907852837564279074904382605163141518161494337  #(one of the parameters of elliptic curve)

        #https://bitcoin.stackexchange.com/questions/58853/how-do-you-figure-out-the-r-and-s-out-of-a-signature-using-python

        sign_bytes_hex = binascii.hexlify(sign_bytes).decode('ascii')
        len_r = int(sign_bytes_hex[6:8],16)
        r = sign_bytes_hex[8:8 + 2* len_r]
        len_s = int(sign_bytes_hex[8 + 2* len_r  + 2 : 8 + 2* len_r + 2 + 2],16)
        s = int(sign_bytes_hex[8 + 2* len_r + 2 + 2 : 8 + 2* len_r + 2 + 2 + 2*len_s],16)

        if s > N/2:
            s = N - s
            s_hex = intToHex(s)
            sign_bytes_hex = '02' + intToHex(len_r) + r + '02' + intToHex(int(len(s_hex)/2)) + s_hex
            sign_bytes_hex = '30' + intToHex(int(len(sign_bytes_hex)/2)) + sign_bytes_hex
            sign_bytes = binascii.unhexlify(sign_bytes_hex)



        sign_bytes += bytes([1])
        sign_bytes =  struct.pack("<B", len(sign_bytes)) + sign_bytes


        vk = sk.verifying_key

        public_key_bytes = (bytes([4]) + vk.to_string())
        public_key_bytes = struct.pack("<B", len(public_key_bytes)) + public_key_bytes

        # Creating unlocking scipt (scriptSig)
        # <sig><PubK>
        sigscript =  sign_bytes + public_key_bytes

        sigscripts[outpoint_hash] = sigscript

    signed_txn =  makeRowTransaction(prev_outputs, sigscripts, receivers)
    return signed_txn


def getSignedTran(outputs, my_address, private_key,  receivers, ischeckbalance = True,  fee = -1):

    #get amount of bitcoin on adress
    address_balance = utils_bitcoin.getBalanceByAddress(my_address)

    total_value_to_sent = 0

    for addrr, value in receivers.items():
        total_value_to_sent += value

    if ischeckbalance:
        if total_value_to_sent > address_balance:
            raise Exception('Exceeding balance of address. Attempt of sending %d. Actual balance is %d' % (total_value_to_sent, address_balance))


    value_back = address_balance - total_value_to_sent
    if value_back <0:
        value_back = 0

    if fee < 0:
        # it's necessary to calculate appropriate fee
        recomended_fee_per_byte = utils_bitcoin.getRecomendedFee()

        # Estimating size of transaction
        if recomended_fee_per_byte > 0 :
            receiversTemp = dict((addrr, value) for addrr, value in receivers.items())

            if value_back > 0:
                if my_address in receiversTemp:
                    receiversTemp[my_address] += value_back
                else:
                    receiversTemp[my_address] = value_back

            sizeInBytes = len(makeSignTransaction(outputs, private_key, my_address, receiversTemp))

            # the final fee
            fee = sizeInBytes * recomended_fee_per_byte
        else:
            fee = 0
        print('Calculated fee for this transaction %d' % fee)


    value_back -= fee
    if value_back < 0:
        value_back = 0

    if value_back > 0:
        print('Rest of satoshi on sender adress will be %d' % value_back)


    if value_back > 0:
        if my_address in receivers:
            receivers[my_address] += value_back
        else:
            receivers[my_address] = value_back


    txn = makeSignTransaction(outputs, private_key, my_address, receivers)

    verify(binascii.hexlify(txn).decode('ascii'), my_address)

    return txn


def verify(txnHex, senderAdress):
    class Verify_data():
        def __init__(self, pub, sig, scriptToSign):
            self.pub = pub
            self.sig = sig
            self.scriptToSign = scriptToSign


    first = txnHex[0:5 * 2]  # version + tx_in_count

    tx_in_count = int(txnHex[2*4:2*5])

    ps = 4 + 1
    tx_current = 0

    scriptToSignList = []
    outpointList     = []

    while tx_current < tx_in_count:
        tx_current += 1
        outpoint = txnHex[(ps * 2):(ps + 36) * 2]
        outpointList.append(outpoint)
        ps += 36
        scriptLen = int(txnHex[ps * 2:(ps + 1) * 2], 16)
        ps += 1 + scriptLen + 4

    ps = 4 + 1
    tx_current = 0

    while tx_current < tx_in_count:
        ps +=  36
        scriptLen = int(txnHex[ps * 2:(ps + 1) * 2], 16)
        script = txnHex[(ps + 1) * 2:(ps + 1 + scriptLen) * 2]
        sequence = txnHex[(ps + 1 + scriptLen) * 2 : (ps + 1 + scriptLen + 4) * 2]
        ps +=  1 + scriptLen + 4

        sigLen = int(script[0:2], 16)
        sig = script[2:2 + sigLen * 2]

        assert (sig[-2:] == '01')  # hashtype

        pubLen = int(script[2 + sigLen * 2:2 + sigLen * 2 + 2], 16)
        pub = script[2 + sigLen * 2 + 2:]

        addr = utils_bitcoin.pubKeyToAddr(pub)
        assert(senderAdress == addr)

        tx_current_inner = 0
        scriptToSign = ''
        while tx_current_inner < tx_in_count:
            if tx_current_inner == tx_current:
                scriptToSign += outpointList[tx_current_inner] + "1976a914" + binascii.hexlify(base58.b58decode_check(addr)[1:]).decode('ascii') + "88ac" + sequence
            else:
                scriptToSign += outpointList[tx_current_inner] + '00' + sequence

            tx_current_inner += 1

        tx_current += 1

        scriptToSignList.append(Verify_data(pub, sig, scriptToSign))

    rest = txnHex[(ps) * 2 :]


    for verify_data in scriptToSignList:
        signableTxn = first + verify_data.scriptToSign +  rest + "01000000"
        hashToSign = binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify(signableTxn)).digest()).digest())
        vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(verify_data.pub[2:]), curve=ecdsa.SECP256k1)
        assert (vk.verify_digest(binascii.unhexlify(verify_data.sig[:-2]), binascii.unhexlify(hashToSign), ecdsa.util.sigdecode_der))



if __name__ == '__main__':

    '''
    getSignedTran(previous_output, output_index, sender_address, private_key,  receivers, ischeckbalance = True, fee = -1)
    
    Params 
    1. outputs         - dict of previous outputs in format {'output':'output_index'}
    2. sender_adress       - sender address 
    3. private_key     - private key for sender address
    4. receivers       - dict of receiver in format {'address':'amount of nitcoin in satoshi'}. It's possible to send to several addresses
    5. ischeckbalance  - check before creating transaction if there is enough bitcoins on my_adress
    6. fee             - Amount of fee for miners. You can put here aby fee. If this param is negative, fee will be calculated based on recomendation of bitcoin network
                         The more fee the faster transaction will be proceed. You can try put the fee as much as zero (0), in this case transaction will be proceed with the lowest priority or may be never)
    
    Below is an example for address 1P6JWvHNrKcRWmZcQowJBR4nceYLXvevA6
    
    You can see detail on this link:
    https://www.blockchain.com/en/btc/address/1P6JWvHNrKcRWmZcQowJBR4nceYLXvevA6
    
    '''
    outputs  = {"3e677f52f460db0cb152301b9ab456c8d56219370c4ad8f8c6d82b7dbc707235": 0}
    sender_address      = "1P6JWvHNrKcRWmZcQowJBR4nceYLXvevA6"
    private_key     = "6ce2705f8ca8ddb113de18a76aa7d83483a142978d316d6f526ccc95411a5157"

    receivers = {"1694jeVGow1MQ6qp1kA4LA9Xi4LkKYj2aP": 140000}


    txn = getSignedTran(outputs, sender_address, private_key,  receivers, False)
    txnHex = binascii.hexlify(txn).decode('ascii')

    # To decode this Hex you can use https://live.blockcypher.com/btc/decodetx/
    print(txnHex)






