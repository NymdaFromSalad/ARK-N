import socket
import threading
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom

# 256-bit pre-shared key (must be same on both client and server)
PSK = b"this_is_your_32_byte_pre_shared_key!!"

# Replace with your actual server where you want to tunnel SOCKS data
YOUR_SERVER_HOST = '127.0.0.1'
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
        # 1. Handshake
        ver = client_sock.recv(1)
        if ver != b'\x05':
            client_sock.close()
            return
        nmethods = ord(client_sock.recv(1))
        methods = client_sock.recv(nmethods)
        # We support no authentication only (0x00)
        client_sock.sendall(b'\x05\x00')

        # 2. Request
        ver_cmd_rsv_atyp = recv_all(client_sock, 4)
        ver, cmd, rsv, atyp = struct.unpack('!BBBB', ver_cmd_rsv_atyp)
        if ver != 5 or cmd != 1:  # Only CONNECT supported
            # Reply: command not supported
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
            # Address type not supported
            client_sock.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            client_sock.close()
            return

        port_bytes = recv_all(client_sock, 2)
        port = struct.unpack('!H', port_bytes)[0]

        # print(f"SOCKS request for {addr}:{port}")

        # 3. Connect to your server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((YOUR_SERVER_HOST, YOUR_SERVER_PORT))

        # Send destination info in simple format: "<addr>:<port>\n"
        dest_info = f"{addr}:{port}\n".encode()
        server_sock.sendall(dest_info)

        # 4. Reply success to client
        reply = b'\x05\x00\x00\x01'  # VER, REP=0 (success), RSV, ATYP=IPv4
        reply += socket.inet_aton('0.0.0.0') + b'\x00\x00'  # BND.ADDR = 0.0.0.0, BND.PORT = 0
        client_sock.sendall(reply)

        # 5. Relay data between client_sock <-> server_sock
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception as e:
                print(f"Exception in forward: {e}")
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception as e:
                    print(f"Exception in forward's finally: {e}")
                    pass

        t1 = threading.Thread(target=forward, args=(client_sock, server_sock))
        t2 = threading.Thread(target=forward, args=(server_sock, client_sock))
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
