import asyncio
import struct
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom

PSK = b"this_is_your_32_byte_pre_shared_"
PROXY_CHUNK_SIZE = 1024 * 16
CHUNK_LEN_BYTES = (PROXY_CHUNK_SIZE.bit_length() + 7) // 8  # = 3
print(CHUNK_LEN_BYTES)
#YOUR_SERVER_HOST = '127.0.0.1'
YOUR_SERVER_HOST = '95.164.116.247'
YOUR_SERVER_PORT = 9999


async def recv_all(reader: asyncio.StreamReader, n: int) -> bytes:
    data = b''
    while len(data) < n:
        more = await reader.read(n - len(data))
        if not more:
            raise ConnectionError("Socket closed prematurely")
        data += more
    return data


async def handle_socks_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
):
    try:
        ver = await reader.read(1)
        if ver != b'\x05':
            writer.write(b'\x05\xff')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        nmethods = (await reader.read(1))[0]
        methods = await reader.read(nmethods)

        if b'\x00' not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        writer.write(b'\x05\x00')
        await writer.drain()

        ver_cmd_rsv_atyp = await recv_all(reader, 4)
        ver, cmd, rsv, atyp = struct.unpack('!BBBB', ver_cmd_rsv_atyp)

        if ver != 5 or cmd != 1:
            writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        if atyp == 1:
            addr = socket.inet_ntoa(await recv_all(reader, 4))
        elif atyp == 3:
            length = (await reader.read(1))[0]
            addr = (await reader.read(length)).decode()
        elif atyp == 4:
            addr = socket.inet_ntop(
                socket.AF_INET6,
                await recv_all(reader, 16)
            )
        else:
            writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        port = struct.unpack('!H', await recv_all(reader, 2))[0]

        try:
            (
                remote_reader, remote_writer
            ) = await asyncio.open_connection(
                YOUR_SERVER_HOST, YOUR_SERVER_PORT
            )
        except Exception as e:
            print("Failed to connect to relay:", e)
            writer.close()
            await writer.wait_closed()
            return

        dest_info = f"{addr}:{port}\n".encode()
        iv_c2s = urandom(12)
        iv_s2c = urandom(12)
        remote_writer.write(dest_info + iv_c2s + iv_s2c)
        await remote_writer.drain()

        reply = b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + b'\x00\x00'
        writer.write(reply)
        await writer.drain()

        async def encrypt_forward(src_reader, dst_writer, iv, label):
            aesgcm = AESGCM(PSK)
            try:
                while True:
                    data = await src_reader.read(PROXY_CHUNK_SIZE)
                    if not data:
                        break
                    encrypted = aesgcm.encrypt(iv, data, None)
                    dst_writer.write(
                        len(encrypted).to_bytes(CHUNK_LEN_BYTES, 'big')
                        + encrypted
                    )
                    await dst_writer.drain()
            except (
                asyncio.IncompleteReadError, ConnectionResetError,
                ConnectionError, asyncio.CancelledError
            ):
                pass
            except Exception as e:
                print(f"[{label}](enc) Exception {type(e)}: {e}")
            finally:
                dst_writer.close()

        async def decrypt_forward(src_reader, dst_writer, iv, label):
            aesgcm = AESGCM(PSK)
            try:
                while True:
                    size_bytes = await recv_all(src_reader, CHUNK_LEN_BYTES)
                    size = int.from_bytes(size_bytes, 'big')
                    encrypted = await recv_all(src_reader, size)
                    decrypted = aesgcm.decrypt(iv, encrypted, None)
                    dst_writer.write(decrypted)
                    await dst_writer.drain()
            except (
                asyncio.IncompleteReadError, ConnectionResetError,
                ConnectionError, asyncio.CancelledError
            ):
                pass
            except Exception as e:
                print(f"[{label}](dec) Exception {type(e)}: {e}")
            finally:
                dst_writer.close()

        await asyncio.gather(
            encrypt_forward(reader, remote_writer, iv_c2s, "client→server"),
            decrypt_forward(remote_reader, writer, iv_s2c, "server→client")
        )
    except ConnectionError:  # as e:
        pass  # print(f"Closing connection: {e}")
    except Exception as e:
        print("Error:", e)
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    server = await asyncio.start_server(handle_socks_client, '127.0.0.1', 1080)
    print("SOCKS5 proxy listening on 127.0.0.1:1080")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
