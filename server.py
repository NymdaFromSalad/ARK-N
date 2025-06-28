# relay_server.py
import asyncio
from socket import gaierror
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom

# 256-bit pre-shared key (must be same on both client and server)
PSK = b"this_is_your_32_byte_pre_shared_"

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
        remote_reader, remote_writer = await asyncio.open_connection(host, port)

        # Step 2: Read both IVs from client
        iv_c2s = await reader.readexactly(12)
        iv_s2c = await reader.readexactly(12)
        # print(f"[handle_client] IV client→server: {iv_c2s.hex()}")
        # print(f"[handle_client] IV server→client: {iv_s2c.hex()}")

        aesgcm_c2s = AESGCM(PSK)
        aesgcm_s2c = AESGCM(PSK)

        # Decrypting client → server
        async def pipe_decrypt(r, w, aesgcm, iv):
            try:
                while True:
                    size_bytes = await r.readexactly(2)
                    size = int.from_bytes(size_bytes, 'big')
                    encrypted = await r.readexactly(size)
                    decrypted = aesgcm.decrypt(iv, encrypted, None)
                    w.write(decrypted)
                    await w.drain()
            except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.CancelledError):
                pass
            finally:
                try:
                    w.close()
                    await w.wait_closed()
                except:
                    pass

        # Encrypting server → client
        async def pipe_encrypt(r, w, aesgcm, iv):
            try:
                while True:
                    data = await r.read(4096)
                    if not data:
                        break
                    encrypted = aesgcm.encrypt(iv, data, None)
                    w.write(len(encrypted).to_bytes(2, 'big') + encrypted)
                    await w.drain()
            except (ConnectionResetError, asyncio.CancelledError):
                pass
            finally:
                try:
                    w.close()
                    await w.wait_closed()
                except:
                    pass

        await asyncio.gather(
            pipe_decrypt(reader, remote_writer, aesgcm_c2s, iv_c2s),  # client → website
            pipe_encrypt(remote_reader, writer, aesgcm_s2c, iv_s2c)   # website → client
        )

    except Exception as e:
        print("Connection error:", e)
        writer.close()


IP = '0.0.0.0'
PORT = 9999


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
