import struct

from Crypto.Cipher import AES
from Crypto.Hash import HMAC

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # The initial connection handshake for agreeing on a shared secret
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Sets the variables required for encryption and hashing
        IV = '\x16'*16
        shared_hash = bytes(shared_hash,"ascii")
        self.cipher = AES.new(shared_hash[:32], AES.MODE_CFB, IV)
        self.hmac = HMAC.new(shared_hash[:32])

    def send(self, data):
        if self.cipher:
            # Encrypts the data
            encrypted_data = self.cipher.encrypt(data)
            # Hashes the encrypted data using HMAC
            self.hmac.update(encrypted_data)
            # Appends the data alongside the existing encrypted data
            encrypted_data += self.hmac.digest();

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data
            self.hmac.update(encrypted_data)
            encrypted_data += self.hmac.digest();

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        
        if self.cipher:
            # Compares sent HMAC and calculated HMAC to determine integrity
            self.hmac.update(encrypted_data[:-self.hmac.digest_size])
            if (self.hmac.digest() != encrypted_data[-self.hmac.digest_size:]):
                print("Error HMAC does not match sent HMAC")
                return b''

            # Decrypts the recieved text
            data = self.cipher.decrypt(encrypted_data[:-self.hmac.digest_size])
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = self.cipher.decrypt(encrypted_data[:-self.hmac.digest_size])
            
        return data

    def close(self):
        self.conn.close()
