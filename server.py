# relay_server.py
import asyncio
from socket import gaierror
from sys import platform
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
# , AESGCM
from hashlib import sha256
# from os import urandom

# 256-bit pre-shared key (must be same on both client and server)
KEY = "Anything"
PSK = sha256(KEY.encode()).digest()

PROXY_CHUNK_SIZE = 1024 * 256
CHUNK_LEN_BYTES = (PROXY_CHUNK_SIZE.bit_length() + 7) // 8  # = 3
print(CHUNK_LEN_BYTES)
IP = '0.0.0.0'
PORT = 9984


async def safe_read(r, n, timeout=30):
    try:
        return await asyncio.wait_for(r.read(n), timeout)
    except asyncio.TimeoutError:
        print("Read timeout, closing connection")
        raise
    except OSError as e:
        if platform == 'win32' and getattr(e, 'winerror', None) == 121:
            print("Windows semaphore timeout occurred, closing connection")
            return
        raise
    except BrokenPipeError as e:
        print(f"BPE in SR: {e}")
        raise


async def safe_read_exactly(r, n, timeout=30):
    try:
        return await asyncio.wait_for(r.readexactly(n), timeout)
    except asyncio.TimeoutError:
        print("Read timeout, closing connection")
        raise
    except OSError as e:
        if platform == 'win32' and getattr(e, 'winerror', None) == 121:
            print("Windows semaphore timeout occurred, closing connection")
            return
        raise
    except BrokenPipeError as e:
        print(f"BPE in SRE: {e}")
        raise


async def handle_client(reader, writer):
    try:
        # Step 1: Read destination line
        line = await reader.readline()
        line = line.decode().strip()
        if not line:
            writer.close()
            return

        # Handle IPv6 or IPv4
        if line.startswith('['):
            host_port_split = line.rsplit(']:', 1)
            if len(host_port_split) != 2:
                writer.close()
                return
            host = host_port_split[0][1:]
            port = int(host_port_split[1])
        else:
            if ':' not in line:
                writer.close()
                return
            host, port_str = line.rsplit(':', 1)
            port = int(port_str)

        print(f"Connecting to {host}:{port}")
        (
            remote_reader, remote_writer
        ) = await asyncio.open_connection(host, port)

        # Step 2: Read both IVs from client
        iv_c2s = await reader.readexactly(12)
        iv_s2c = await reader.readexactly(12)
        # print(f"[handle_client] IV client→server: {iv_c2s.hex()}")
        # print(f"[handle_client] IV server→client: {iv_s2c.hex()}")

        cypher_c2s = ChaCha20Poly1305(PSK)
        cypher_s2c = ChaCha20Poly1305(PSK)

        # Decrypting client → server
        async def pipe_decrypt(r, w, cypher, iv):
            try:
                while True:
                    size_bytes = await safe_read_exactly(r, CHUNK_LEN_BYTES)
                    size = int.from_bytes(size_bytes, 'big')
                    encrypted = await safe_read_exactly(r, size)
                    decrypted = cypher.decrypt(iv, encrypted, None)
                    w.write(decrypted)
                    await w.drain()
            except (
                asyncio.IncompleteReadError, ConnectionResetError,
                asyncio.TimeoutError, asyncio.CancelledError,
                BrokenPipeError
            ):
                pass  # Pretty much always means
                # connection closed by the other side
            except InvalidTag:
                pass  # Wrong password
            finally:
                try:
                    w.close()
                    await w.wait_closed()
                except (ConnectionResetError, BrokenPipeError) as e:
                    print(f"Connection error during close: {e}")
                except asyncio.CancelledError:
                    raise  # let it propagate
                except Exception as e:
                    print(f"Unexpected error on close: {e}")

        # Encrypting server → client
        async def pipe_encrypt(r, w, cypher, iv):
            try:
                while True:
                    data = await safe_read(r, PROXY_CHUNK_SIZE)
                    if not data:
                        break
                    encrypted = cypher.encrypt(iv, data, None)
                    w.write(
                        len(encrypted).to_bytes(CHUNK_LEN_BYTES, 'big')
                        + encrypted
                    )
                    await w.drain()
            except (
                asyncio.IncompleteReadError, ConnectionResetError,
                asyncio.TimeoutError, asyncio.CancelledError,
                BrokenPipeError
            ):
                pass  # Pretty much always means
                # connection closed by the other side
            finally:
                try:
                    w.close()
                    await w.wait_closed()
                except (ConnectionResetError, BrokenPipeError) as e:
                    print(f"Connection error during close: {e}")
                except asyncio.CancelledError:
                    raise  # let it propagate
                except Exception as e:
                    print(f"Unexpected error on close: {e}")

        await asyncio.gather(
            pipe_decrypt(
                reader,
                remote_writer,
                cypher_c2s,
                iv_c2s
            ),  # client → website
            pipe_encrypt(
                remote_reader,
                writer,
                cypher_s2c,
                iv_s2c
            )   # website → client
        )

    except gaierror as e:
        print("Connection error:", e)
        writer.close()


async def main():
    server = await asyncio.start_server(handle_client, IP, PORT)
    print(f"Server started on {IP}:{PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        exit("\nShutting down...")
