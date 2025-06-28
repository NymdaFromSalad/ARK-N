import socket
import threading
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom

# 256-bit pre-shared key (must be same on both client and server)
PSK = b"this_is_your_32_byte_pre_shared_"

PROXY_CHUNK_SIZE = 4096 * 256
CHUNK_BIT_LEN = PROXY_CHUNK_SIZE.bit_length()
# print(len(PSK))
# exit()

# Replace with your actual server where you want to tunnel SOCKS data
YOUR_SERVER_HOST = '127.0.0.1'
# YOUR_SERVER_HOST = '95.164.116.247'
YOUR_SERVER_PORT = 9999


def recv_all(sock, n):
    """Helper to receive exactly n bytes."""
    data = b''
    while len(data) < n:
        more = sock.recv(n - len(data))
        if not more:
            raise ConnectionError("Socket closed prematurely")
        data += more
    return data


def handle_socks_client(client_sock):
    try:
        # 1. SOCKS5 Handshake
        ver = client_sock.recv(1)
        if ver != b'\x05':
            client_sock.close()
            return
        nmethods = ord(client_sock.recv(1))
        methods = client_sock.recv(nmethods)
        client_sock.sendall(b'\x05\x00')  # No auth

        # 2. SOCKS5 Request
        ver_cmd_rsv_atyp = recv_all(client_sock, 4)
        ver, cmd, rsv, atyp = struct.unpack('!BBBB', ver_cmd_rsv_atyp)
        if ver != 5 or cmd != 1:
            client_sock.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            client_sock.close()
            return

        if atyp == 1:  # IPv4
            addr = socket.inet_ntoa(recv_all(client_sock, 4))
        elif atyp == 3:  # Domain name
            length = ord(client_sock.recv(1))
            addr = client_sock.recv(length).decode()
        elif atyp == 4:  # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, recv_all(client_sock, 16))
        else:
            client_sock.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            client_sock.close()
            return

        port_bytes = recv_all(client_sock, 2)
        port = struct.unpack('!H', port_bytes)[0]

        # 3. Connect to your server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((YOUR_SERVER_HOST, YOUR_SERVER_PORT))

        # 4. Send destination + IVs to server
        dest_info = f"{addr}:{port}\n".encode()
        iv_c2s = urandom(12)
        iv_s2c = urandom(12)
        server_sock.sendall(dest_info + iv_c2s + iv_s2c)
        # print(f"[client] IV client→server: {iv_c2s.hex()}")
        # print(f"[client] IV server→client: {iv_s2c.hex()}")

        # 5. Reply success to local client
        reply = b'\x05\x00\x00\x01'  # success
        reply += socket.inet_aton('0.0.0.0') + b'\x00\x00'
        client_sock.sendall(reply)

        # 6. Forward encrypted and decrypted streams
        def encrypt_forward(src, dst, iv, label):
            try:
                aesgcm = AESGCM(PSK)
                while True:
                    data = src.recv(PROXY_CHUNK_SIZE)
                    if not data:
                        break
                    encrypted = aesgcm.encrypt(iv, data, None)
                    dst.sendall(len(encrypted).to_bytes(CHUNK_BIT_LEN, 'big') + encrypted)
                    # print(f"[{label}] Encrypted block size: {len(encrypted)}")
            except Exception as e:
                print(f"[{label}] Exception: {e}")
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception as e:
                    print(f"[{label}] shutdown error: {e}")

        def decrypt_forward(src, dst, iv, label):
            try:
                aesgcm = AESGCM(PSK)
                while True:
                    size_bytes = recv_all(src, CHUNK_BIT_LEN)
                    size = int.from_bytes(size_bytes, 'big')
                    encrypted = recv_all(src, size)
                    decrypted = aesgcm.decrypt(iv, encrypted, None)
                    dst.sendall(decrypted)
                    # print(f"[{label}] Decrypted block size: {len(decrypted)}")
            except Exception as e:
                print(f"[{label}] Exception: {e}")
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception as e:
                    print(f"[{label}] shutdown error: {e}")

        # Start threads for both directions
        t1 = threading.Thread(target=encrypt_forward, args=(client_sock, server_sock, iv_c2s, "client→server"))
        t2 = threading.Thread(target=decrypt_forward, args=(server_sock, client_sock, iv_s2c, "server→client"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        print("Error:", e)
    finally:
        client_sock.close()
        try:
            server_sock.close()
        except:
            pass


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 1080))
    sock.listen(5)
    print("SOCKS5 proxy listening on 127.0.0.1:1080")

    while True:
        client_sock, addr = sock.accept()
        threading.Thread(target=handle_socks_client, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()
