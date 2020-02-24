import socket
import time
import sys
import nstp_v3_pb2
from _thread import *
import hashlib
import nacl.utils
import nacl.bindings
from passlib.hash import sha256_crypt
from passlib.hash import sha512_crypt
from passlib.hash import md5_crypt
from passlib.hash import argon2

initialized = {}  # Conns per ip
auth_tries = {}  # Auth tries per ip
rate_ip = {}  # Rate per ip
public_store = {}


class SessionKeys:
    server_pk = None
    server_sk = None
    server_rx = None
    server_tx = None
    user_store = {}
    conn_ip = None

    def set(s_pk, s_sk, s_rx, s_tx):
        SessionKeys.server_pk = s_pk
        SessionKeys.server_sk = s_sk
        SessionKeys.server_rx = s_rx
        SessionKeys.server_tx = s_tx

    def get(val):
        if val == 'server_pk':
            return SessionKeys.server_pk
        elif val == 'server_sk':
            return SessionKeys.server_sk
        elif val == 'server_rx':
            return SessionKeys.server_rx
        else:
            return SessionKeys.server_tx



def authenticator(username, password):
    if auth_tries.get(SessionKeys.conn_ip) is None:
        auth_tries[SessionKeys.conn_ip] = 0
    auth_tries[SessionKeys.conn_ip] = auth_tries.get(SessionKeys.conn_ip) + 1
    if auth_tries.get(SessionKeys.conn_ip) < 10:
        print(sys.argv[1])
        with open(sys.argv[1]) as f:                                    #Change to sys.argv after testing
            lines = f.readlines()
            for line in lines:
                splitted_line = line.split(":")
                if splitted_line[0] == username:
                    hash_type = line.split("$")[1]
                    hash = splitted_line[1][0:len(splitted_line[1]) - 1]
                    if hash_type == '6':
                        return sha512_crypt.verify(password, hash)
                    if hash_type == '5':
                        return sha256_crypt.verify(password, hash)
                    if hash_type == '1':
                        return md5_crypt.verify(password, hash)
                    if hash_type == 'argon2id':
                        return argon2.verify(password, hash)
    if auth_tries.get(SessionKeys.conn_ip) >= 10:
        rate_ip[SessionKeys.conn_ip] = 5
    return False


class AfterInitialized:
    def auth_request_handler(msg):
        decrypted_message = nstp_v3_pb2.DecryptedMessage()
        authenticated = authenticator(msg.auth_request.username, msg.auth_request.password)
        if authenticated == -1:
            return -1
        decrypted_message.auth_response.authenticated = authenticated
        nonce = nacl.bindings.randombytes(nacl.bindings.crypto_secretbox_NONCEBYTES)
        ciphertext = nacl.bindings.crypto_secretbox(decrypted_message.SerializeToString(), nonce,
                                               SessionKeys.get('server_tx'))
        auth_response = nstp_v3_pb2.NSTPMessage()
        auth_response.encrypted_message.ciphertext = ciphertext
        auth_response.encrypted_message.nonce = nonce
        len_hex = bytes.fromhex("{:04x}".format(auth_response.ByteSize()))
        return len_hex + auth_response.SerializeToString()

    def ping_request_handler(msg):
        hash_algo = msg.ping_request.hash_algorithm
        decrypted_message = nstp_v3_pb2.DecryptedMessage()
        if hash_algo == 0:
            decrypted_message.ping_response.hash = msg.ping_request.data
        if hash_algo == 1:
            decrypted_message.ping_response.hash = hashlib.sha256(msg.ping_request.data).digest()
        if hash_algo == 2:
            decrypted_message.ping_response.hash = hashlib.sha512(msg.ping_request.data).digest()
        nonce = nacl.bindings.randombytes(nacl.bindings.crypto_secretbox_NONCEBYTES)
        ciphertext = nacl.bindings.crypto_secretbox(decrypted_message.SerializeToString(), nonce,
                                               SessionKeys.get('server_tx'))
        ping_response = nstp_v3_pb2.NSTPMessage()
        ping_response.encrypted_message.ciphertext = ciphertext
        ping_response.encrypted_message.nonce = nonce
        len_hex = bytes.fromhex("{:04x}".format(ping_response.ByteSize()))
        return len_hex + ping_response.SerializeToString()

    def load_request_handler(msg):
        if msg.load_request.public == False:
            value = SessionKeys.user_store.get(msg.load_request.key)
        else:
            value = public_store.get(msg.load_request.key)
        if value == None:
            value = b''
        decrypted_message = nstp_v3_pb2.DecryptedMessage()
        decrypted_message.load_response.value = value
        nonce = nacl.bindings.randombytes(nacl.bindings.crypto_secretbox_NONCEBYTES)
        ciphertext = nacl.bindings.crypto_secretbox(decrypted_message.SerializeToString(), nonce,
                                               SessionKeys.get('server_tx'))
        load_response = nstp_v3_pb2.NSTPMessage()
        load_response.encrypted_message.ciphertext = ciphertext
        load_response.encrypted_message.nonce = nonce
        len_hex = bytes.fromhex("{:04x}".format(load_response.ByteSize()))
        return len_hex + load_response.SerializeToString()

    def store_request_handler(msg):
        key = msg.store_request.key
        value = msg.store_request.value
        if msg.store_request.public == False:
            SessionKeys.user_store[key] = value
        else:
            public_store[key] = value
        decrypted_message = nstp_v3_pb2.DecryptedMessage()
        decrypted_message.store_response.hash = hashlib.sha256(value).digest()
        decrypted_message.store_response.hash_algorithm = 1
        nonce = nacl.bindings.randombytes(nacl.bindings.crypto_secretbox_NONCEBYTES)
        ciphertext = nacl.bindings.crypto_secretbox(decrypted_message.SerializeToString(), nonce,
                                               SessionKeys.get('server_tx'))
        store_response = nstp_v3_pb2.NSTPMessage()
        store_response.encrypted_message.ciphertext = ciphertext
        store_response.encrypted_message.nonce = nonce
        len_hex = bytes.fromhex("{:04x}".format(store_response.ByteSize()))
        return len_hex + store_response.SerializeToString()


def key_pair_generator(client_pk):
    server_pk, server_sk = nacl.bindings.crypto_box_keypair()
    server_rx, server_tx = nacl.bindings.crypto_kx_server_session_keys(server_pk, server_sk, client_pk)
    SessionKeys.set(server_pk, server_sk, server_rx, server_tx)


def server_hello(client_hello):
    print("Client_hello aagaya")
    key_pair_generator(client_hello.public_key)
    if client_hello.major_version == 3:
        server_hello_response = nstp_v3_pb2.NSTPMessage()
        server_hello_response.server_hello.major_version = 3
        server_hello_response.server_hello.minor_version = 2
        server_hello_response.server_hello.user_agent = "Client_Authentication"
        server_hello_response.server_hello.public_key = SessionKeys.get("server_pk")
        print(SessionKeys.get("server_pk"))
        len_hex = bytes.fromhex("{:04x}".format(server_hello_response.ByteSize()))
        return len_hex + server_hello_response.SerializeToString()
    return -1


def decrypt_message(input):
    print(input.ciphertext)
    decrypted_message = nstp_v3_pb2.DecryptedMessage()
    decrypted = nacl.bindings.crypto_secretbox_open(input.ciphertext, input.nonce, SessionKeys.get("server_rx"))
    decrypted_message.ParseFromString(decrypted)
    print(decrypted_message)
    msg_name = decrypted_message.WhichOneof('message_')
    check_response = getattr(AfterInitialized, msg_name + "_handler")(decrypted_message)
    return check_response


def error_message():
    error = nstp_v3_pb2.NSTPMessage()
    error.error_message.error_message = "I am terminating you"
    len_hex = bytes.fromhex("{:04x}".format(error.ByteSize()))
    return len_hex + error.SerializeToString()


def decider(input):
    print("idharse")
    if input.WhichOneof('message_') == 'client_hello':
        if initialized.get(SessionKeys.conn_ip) is None:
            initialized[SessionKeys.conn_ip] = 0
        initialized[SessionKeys.conn_ip] = initialized.get(
            SessionKeys.conn_ip) + 1  # Setting number of connections from an ip.
        return server_hello(input.client_hello)
    if SessionKeys.conn_ip in initialized:
        return decrypt_message(input.encrypted_message)

    return -1


def recv_input(c):
    nstp_msg = nstp_v3_pb2.NSTPMessage()
    data = c.recv(4096)
    response = -1
    if data:
        len_hex = hex(data[0]) + format(data[1], 'x')
        if len(data) == int(len_hex, 0) + 2:
            nstp_msg.ParseFromString(data[2:])
            print(nstp_msg)
            response = decider(nstp_msg)
        return response


def threaded(c, addr):
    if rate_ip.get(addr[0]) is None:
        rate_ip[addr[0]] = 0
    SessionKeys.conn_ip = addr[0]
    try:
        while True:
            response = recv_input(c)
            if response == -1:
                raise Exception('Failure', 'Some Errorrrrr')
            c.send(response)
            time.sleep(rate_ip.get(addr[0]))  # R is the aggregate rate
    except:
        print("Cutting you off because of the limit on auth_tries")

    finally:
        c.close()


def Main():
    host = "0.0.0.0"
    port = 22300
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        print("socket binded to port", port)
    except:
        print("Socket Bind Error")
    s.listen()
    print("socket is listening")
    while True:
        c, addr = s.accept()
        print('Connected to :', addr[0], ':', addr[1])
        try:
            start_new_thread(threaded, (c, addr))
        except:
            print("Some problem with starting the thread.")
    s.close()


if __name__ == '__main__':
    Main()
