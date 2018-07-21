import time
import struct
import random
import hashlib
from datetime import datetime
import calendar
import binascii
from threading import Thread
from threading import Event
from queue import Queue
import utils_bitcoin
import socket


ping_interval_sec = 10

class Socket_data():
    def __init__(self, command, buf):
        self.command = command
        self.buf = buf

    def __str__(self):
        # for debug mostly
        if self.command == "version":
            version, services, timestamp, addr_recv, addr_from, nonce = struct.unpack('<LQQ26s26sQ', self.buf[:80])
            return '%s : %d addr_recv : %d.%d.%d.%d:%d' % (self.command, version, addr_recv[20], addr_recv[21], addr_recv[22], addr_recv[23], struct.unpack('!H', addr_recv[24:26])[0])
        elif self.command == "pong":
            return '%s, nonce = %d ' % (self.command,  struct.unpack("Q", self.buf)[0])
        elif self.command == "ping":
            return '%s, nonce = %d ' % (self.command,  struct.unpack("Q", self.buf)[0])
        elif self.command == "inv":
            return '%s, count  = %d ' % (self.command, struct.unpack("<L", self.buf[:4])[0])
        elif self.command == "reject":
            return '%s, details: %s ' % (self.command, self.buf)
        else:
            return '%s , len = %d' % (self.command, len(self.buf))


class Simple_node():
    def __init__(self, ip_to_connect = ''):
        self.exit_event = Event()
        self.sock = utils_bitcoin.getSocket(ip_to_connect)

    def makeMessage(self, cmd, payload):
        magic = binascii.unhexlify("F9BEB4D9") # Main network ID
        command = cmd + (12 - len(cmd)) * "\00"
        commandbyte =  bytes(command, "utf-8")

        length = struct.pack("I", len(payload))

        check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
        return magic + commandbyte + length + check + payload


    def versionMessage(self):

        def convertadress( ar):
            while len(ar) < 16:
                ar = bytes([0]) + ar
            return ar
        # description of protocol is here https://en.bitcoin.it/wiki/Protocol_documentation#version
        version = struct.pack("i", 70002) # 4 version	int32_t
        services = struct.pack("Q", 0)    # 8	services	uint64_t

        d = datetime.utcnow()
        unixtime = calendar.timegm(d.utctimetuple())
        timestamp = struct.pack("q", unixtime)  #8	timestamp	int64_t

        #https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
        addr_recv = struct.pack("Q", 0)                #8	services	uint64_t
        addr_recv += convertadress(bytes([127,0,0,1])) #16	IPv6/4	char[16]
        addr_recv += struct.pack(">H", 8333)           #2	port	uint16_t

        addr_from = struct.pack("Q", 0)                 #8	services	uint64_t
        addr_from += convertadress(bytes([127,0,0,1])) #16	IPv6/4	char[16]
        addr_from += struct.pack(">H", 8333)            #2	port	uint16_t

        nonce = struct.pack("Q", random.getrandbits(64)) #8	nonce	uint64_t
        user_agent = struct.pack("B", 0) #   Anything
        height = struct.pack("i", 0)     #4  start_height	int32_t , Block number, doesn't matter
        relay =  struct.pack("b", 1)     #1	 relay	bool



        payload = version + services + timestamp + addr_recv + addr_from + nonce + user_agent + height + relay

        return payload

    def decodemes(self, data):
        # first 24 bytes are header
        # https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
        print(len(data))
        if len(data) < 24:
            return ''
        header = data[:24]

        magic = binascii.hexlify(header[:4])
        command = header[4:16].decode('ascii')
        command = command.replace('\0', '')
        length = struct.unpack("I", header[16:20])
        payload = data[24: 24 + length[0]]


        return  command, length, payload

    def getdata(self):
        while True:
            header = self.sock.recv(24)
            if len(header) == 0:
                break
            magic, cmd, payload_len, checksum = struct.unpack('<L12sL4s', header)
            buf = bytes()
            while payload_len > 0:
                chunk = self.sock.recv(payload_len)
                if len(chunk) == 0:
                    break
                buf += chunk
                payload_len -= len(chunk)

            command =cmd.decode('ascii')
            command = command.replace('\0', '')  # Remove null termination

            yield Socket_data(command, buf)

    def messagehandler(self, data):
        queue = Queue()

        def _run(exitEvent):
            for socket_data in data:

                if exitEvent.is_set():
                    break

                if socket_data.command == 'ping':
                    try:
                        self.sock.send(self.makeMessage("pong", socket_data.buf))
                    except Exception as error:
                        print('Error in sending pong message. Details: %s' % error)
                        exitEvent.set()
                        break

                queue.put(socket_data)

                if socket_data.command == 'reject':
                    exitEvent.set()
                    break




        th = Thread(target = _run, args = (self.exit_event,))
        th.daemon = True
        th.start()
        while True:
            yield (queue.get())


    def ping_service(self):

        def _run(exitEvent):

            last_time = time.time() - ping_interval_sec
            while True:

                if exitEvent.is_set():
                    break

                if time.time() - last_time > ping_interval_sec:
                    last_time = time.time()
                else:
                    continue


                p = random.getrandbits(64)
                nonce = struct.pack("Q", p)
                try:

                    self.sock.send(self.makeMessage("ping", nonce))
                except Exception as error:
                    print('Error in sending ping message. Details: %s' % error )
                    exitEvent.set()
                    break


        th = Thread(target=_run, args=(self.exit_event,))
        th.start()


    def start(self, on_get_socked_data = None):

        def _run(exitEvent):
            for socket_data in sdata:
                if on_get_socked_data != None:
                    on_get_socked_data(socket_data)

                if exitEvent.is_set():
                    break



        sdata = self.getdata()

        # send our version to peer
        try:
            self.sock.send(self.makeMessage("version", self.versionMessage()))
        except Exception as error:
            print('Error in sending version message. Details: %s' % error)
            return

        # get here thier version
        socket_data = next(sdata)
        if on_get_socked_data != None:
            on_get_socked_data(socket_data)

        # get here thier verack
        socket_data = next(sdata)
        if on_get_socked_data != None:
            on_get_socked_data(socket_data)

        # vareck
        # send verack message to peer
        try:
            self.sock.send(self.makeMessage("verack", bytes()))
        except Exception as error:
            print('Error in sending verack message. Details: %s' % error)
            self.exit_event.set()
            return


        sdata = self.messagehandler(sdata)

        # To keep connection alive send ping periodically with interval ping_interval_sec
        self.ping_service()

        # listening socket for any messages in the thread
        th = Thread(target=_run, args=(self.exit_event,))
        th.daemon = True
        th.start()


    def send(self, command, data):
        dataMes = self.makeMessage(command, data)
        try:
            self.sock.send(dataMes)
        except Exception as error:
            print('Error in sending command %s. Details: %s' % command, error)



    def send_transaction(self, data):
        self.send('tx', data)

    def stop(self):
        self.exit_event.set()
