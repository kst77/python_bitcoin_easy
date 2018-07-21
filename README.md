
Look for examples in file start_bitcoin.py


1. Generating new private key, public key, address

generate_keys_bitcoin.generate()

2. Creating transaction, sign it and sending to the net

 tx_bitcoin.getSignedTran(previous_output, output_index, sender_address, private_key,  receivers, ischeckbalance = True, fee = -1)
    
   Params 
    1. outputs         - dict of previous outputs in format {'output':'output_index'}
    2. sender_address  - sender address 
    3. private_key     - private key for sender address
    4. receivers       - dict of receiver in format {'address':'amount of nitcoin in satoshi'}. It's possible to send to several addresses
    5. ischeckbalance  - check before creating transaction if there is enough bitcoins on my_adress
    6. fee             - Amount of fee for miners. You can put here aby fee. If this param is negative, fee will be calculated based on recomendation of bitcoin network
                         The more fee the faster transaction will be proceed. You can try put the fee as much as zero (0), in this case transaction will be proceed with the lowest priority or may be never)


Example

sender_address  = "1694jeVGow1MQ6qp1kA4LA9Xi4LkKYj2aP"
private_key     = "581dda14fd1731039b2b0632d5288849daf87f010222a5757b31a82e481c3d64"

receivers = {"1BR1TupFa6AGbnkKqihpYqyEPRfUPZnPrn": 120000, '12b7p5DrNxnTSDMURfWX1RCbbZvsoHnEVi' : 5000}
outputs   = {"b9d934eef14574a614303b702df92572d5016e80f29796a849201b2bcc02d308" : 0, "67f44eebe97cf72a6819274d063642453a3b530a11a61fe5fa9d3d2c32720d3b" : 1}


you can see details for this address here: https://www.blockchain.com/en/btc/address/1694jeVGow1MQ6qp1kA4LA9Xi4LkKYj2aP

txn    = tx_bitcoin.getSignedTran(outputs, sender_address, private_key, receivers)
txnHex = binascii.hexlify(txn).decode('ascii')
print('Transaction hex: ', txnHex)


To decode this Hex you can use https://live.blockcypher.com/btc/decodetx/

Sending transaction to the network

node_bitcoin.Simple_node(ip_to_connect = '')

Params
ip_to_connect - ip of working node in the net. You can find it for example using command "nslookup dnsseed.bluematt.me" or any oyher method. It's also possible to leave this parametr empty, in this case ip of working node  will be found automaticly

Example:

simple_node = node_bitcoin.Simple_node('84.35.69.10')
simple_node = node_bitcoin.Simple_node()

simple_node.send_transaction(txn)



3  Mining

miner_bitcoin.Miner(reciever, message)

 Params 
    1. reciever     - dict of previous outputs in format {'output':'output_index'}
    2. message      - sender address 

 Example:


reciever = '1FGGdEdNtHiQwKnq9YdPPuLU18EA1JoKSC'
message  = 'Mined by me'

miner = miner_bitcoin.Miner(reciever, message)
miner.start()

