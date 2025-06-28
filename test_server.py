import socket
import signal
import sys
import time
from os import urandom

HOST = '127.0.0.1'
PORT = 8080

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)
server.settimeout(1.0)

print(f"Streaming HTTP server running on http://{HOST}:{PORT}")


def shutdown(sig, frame):
    print("\nShutting down server...")
    server.close()
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)

while True:
    try:
        conn, addr = server.accept()
    except socket.timeout:
        continue
    except OSError:
        break

    print(f"Connected by {addr}")
    try:
        request = conn.recv(4096)
        print(f"Request:\n{request.decode(errors='ignore')}")

        # Send chunked transfer-encoded headers
        response_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        )
        conn.sendall(response_headers.encode())

        # Send data in chunks forever
        for _ in range(1024 * 1):
            chunk = urandom(1024 * 1024)  # 1 MB chunk
            # chunk_size = f"{len(chunk):X}\r\n".encode()
            chunk_size = f"{1024 * 1024:X}\r\n".encode()
            conn.sendall(chunk_size + chunk + b"\r\n")
            time.sleep(0)  # optional: limit speed

    except Exception as e:
        print("Client disconnected or error:", e)
    finally:
        try:
            conn.sendall(b"0\r\n\r\n")  # End of chunks if needed
            conn.close()
        except:
            pass
