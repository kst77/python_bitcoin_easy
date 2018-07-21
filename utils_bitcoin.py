import hashlib
import ecdsa
import binascii
import requests
import base58
from websocket import create_connection
from queue import Queue
import json
from threading import Thread
from threading import Event
import socket
import urllib


addressToFindPeers = ['dnsseed.bluematt.me']

def getwsdata(type, count, address = ''):
    ws = create_connection("wss://ws.blockchain.info/inv")
    subscribe = ''
    unsubscribe = ''

    if type == 'utx':
        if address == '':
            subscribe = '{"op":"unconfirmed_sub"}'
            unsubscribe = '{"op":"unconfirmed_unsub"}'
        else:
            subscribe = '{"op": "addr_sub", "addr": "' + address + '"}'
            unsubscribe = '{"op": "addr_unsub", "addr": "' + address + '"}'
    elif type == 'block':
        subscribe = '{"op":"ping_block"}'
        unsubscribe = ''

    if subscribe == '':
        return


    queue = Queue()
    ws.send(subscribe)

    def _run():
        _cnt = 0
        while 1:
            data = json.loads(ws.recv())
            if data['op'] == type:
                queue.put(data)
                _cnt = _cnt + 1
                if _cnt >= count:
                    if unsubscribe != '':
                        ws.send(unsubscribe)
                    ws.close()
                    break


    th = Thread(target=_run, args=())
    th.start()
    cnt = count
    while True:
        yield (queue.get())
        cnt = cnt - 1
        if cnt == 0:
            break


def getBalanceByAddress(addr):
    url = "https://blockchain.info/rawaddr/" + addr + "?format=json"
    try:
        data = requests.get(url).json()
        return data["final_balance"]
    except:
        return -1

def getRecomendedFee():
    url = "https://bitcoinfees.21.co/api/v1/fees/recommended"
    try:
        data = requests.get(url).json()
        return data["fastestFee"]
    except:
        return 0

def getTransactionByAddress(address):
    wsdata = getwsdata('utx', 1, address)
    return  next(wsdata)['x']

def getNewTransactions():
    wsdata = getwsdata('utx', 1000000)
    for d in wsdata:
        yield d['x']


def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))

def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(binascii.unhexlify(s), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return binascii.hexlify(bytes([4]) + vk.to_string()).decode('ascii')

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    n = hashlib.sha256(binascii.unhexlify(s)).digest()
    ripemd160.update(n)
    return base58.b58encode_check(bytes([0]) + ripemd160.digest()).decode('ascii')

def getSocket(ip = ''):

    def trySocketConnect(queue_ip, exitEvent):
        while True:
            if exitEvent.is_set():
                break
            ip_current = queue_ip.get()


            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if sock.connect_ex((ip_current, 8333)) == 0:

                    if exitEvent.is_set():
                        sock.close()
                        break

                    exitEvent.set()
                    queue_socket.put(sock)
                    queue_ip.task_done()
                    print('Used IP for peer connection: %s' % ip_current)
                    break

            except:
                pass



    def fillAdress(queue_addr, queue_ip, exitEvent):
        list_used = []
        while True:
            address = queue_addr.get()
            if exitEvent.is_set():
                break
            try:
                info = socket.getaddrinfo(address, 80)
                for item in info:
                    if exitEvent.is_set():
                        break

                    if socket.AF_INET == item[0]:
                        ip = item[4][0]

                        if ip not in list_used:
                            list_used.append(ip)
                            queue_ip.put(ip)
            except:
                pass



    if ip != '':
        # ip is defined, so connecting to it
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, 8333))
            return sock
        except:
            print('Connection error to host %ip' % ip)
            return
    else:
        num_threads = 4
        queue_ip = Queue()
        queue_socket = Queue()
        queue_addrress = Queue()
        exit_event = Event()

        for addr in addressToFindPeers:
            th_addr = Thread(target=fillAdress, args=(queue_addrress, queue_ip, exit_event,))
            th_addr.daemon = True
            th_addr.start()

        for i in range(num_threads):
            th_sock = Thread(target=trySocketConnect, args=(queue_ip, exit_event,))
            th_sock.daemon = True
            th_sock.start()

        for addr in addressToFindPeers:
            queue_addrress.put(addr)


        queue_ip.join()


        return queue_socket.get()


def getDataForMining(tranCount):
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






