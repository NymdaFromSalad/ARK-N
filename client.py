import asyncio
import struct
import socket
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# AESGCM
from hashlib import sha256
from os import urandom, path as ospath, getcwd
from json import load as jsonload, dump as jsondump
# import sys
from argparse import ArgumentParser

KEY = None
PSK = None
PROXY_CHUNK_SIZE = None
CHUNK_LEN_BYTES = None

LOCAL_HOST = None
LOCAL_PORT = None
REMOTE_HOST = None
REMOTE_PORT = None


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
                REMOTE_HOST, REMOTE_PORT
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
            aesgcm = ChaCha20Poly1305(PSK)
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
            aesgcm = ChaCha20Poly1305(PSK)
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
    except (ConnectionError, ConnectionResetError):  # as e:
        pass  # print(f"Closing connection: {e}")
    except Exception as e:
        print("Error:", e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionResetError, ConnectionAbortedError):
            pass  # I fucking love errors


CONFIG_FILENAME = "proxy_config.json"

DEFAULTS = {
    "LOCAL_HOST": "127.0.0.1",
    "LOCAL_PORT": 1080,
    "REMOTE_HOST": "127.0.0.1",
    "REMOTE_PORT": 9984,
    "KEY": "Anything",
    "PROXY_CHUNK_SIZE": 1024 * 256
}


def get_default_config_path():
    return ospath.join(getcwd(), CONFIG_FILENAME)


def load_config_from_path(path):
    with open(path, "r", encoding="utf-8") as f:
        return jsonload(f)


def merge_config(base, override):
    result = base.copy()
    result.update({k: v for k, v in override.items() if v is not None})
    return result


def parse_args():
    parser = ArgumentParser(
        description=(
            "ARK-N1 proxy, a lightweight and ",
            "totally bug-free encrypted proxy, ",
            "specially designed to bypass RosComNadzor's DPI"
        )
    )
    parser.add_argument("-l", action="store_true",
                        help="Load default config from cwd")
    parser.add_argument("--load-config", action="store_true",
                        help="Load default config from cwd")
    parser.add_argument("--config", type=str,
                        help="Load config from specified file path")
    parser.add_argument("--key", type=str, help="Encryption key")
    parser.add_argument("--local-host", type=str, help="Local listening host")
    parser.add_argument("--local-port", type=int, help="Local listening port")
    parser.add_argument("--remote-host", type=str, help="Remote server host")
    parser.add_argument("--remote-port", type=int, help="Remote server port")
    parser.add_argument("--chunk-size", type=int, help="Proxy chunk size")
    parser.add_argument("--save-config", action="store_true",
                        help="Save provided args to config and exit")
    return parser.parse_args()


async def main():
    args = parse_args()

    # Start with defaults
    config = DEFAULTS.copy()

    # Load config if requested
    if args.load_config or args.l:
        try:
            config_path = get_default_config_path()
            file_config = load_config_from_path(config_path)
            config = merge_config(config, file_config)
            print(f"Loaded config from default path: {config_path}")
        except Exception as e:
            print(f"Failed to load config from default path: {e}")

    elif args.config:
        try:
            file_config = load_config_from_path(args.config)
            config = merge_config(config, file_config)
            print(f"Loaded config from specified path: {args.config}")
        except Exception as e:
            print(f"Failed to load config from specified path: {e}")

    # Merge CLI args (override config)
    cli_override = {
        "KEY": args.key,
        "LOCAL_HOST": args.local_host,
        "LOCAL_PORT": args.local_port,
        "REMOTE_HOST": args.remote_host,
        "REMOTE_PORT": args.remote_port,
        "PROXY_CHUNK_SIZE": args.chunk_size,
    }
    config = merge_config(config, cli_override)

    # Save config and exit if requested
    if args.save_config:
        path_to_save = args.config or get_default_config_path()
        with open(path_to_save, "w", encoding="utf-8") as f:
            jsondump(config, f, indent=2)
        print(f"Config saved to {path_to_save}. Exiting.")
        return

    # Calculate derived values
    KEY = config["KEY"]
    PSK = sha256(KEY.encode()).digest()
    PROXY_CHUNK_SIZE = config["PROXY_CHUNK_SIZE"]
    CHUNK_LEN_BYTES = (PROXY_CHUNK_SIZE.bit_length() + 7) // 8

    LOCAL_HOST = config["LOCAL_HOST"]
    LOCAL_PORT = config["LOCAL_PORT"]
    REMOTE_HOST = config["REMOTE_HOST"]
    REMOTE_PORT = config["REMOTE_PORT"]

    # Update globals
    globals().update({
        "PSK": PSK,
        "PROXY_CHUNK_SIZE": PROXY_CHUNK_SIZE,
        "CHUNK_LEN_BYTES": CHUNK_LEN_BYTES,
        "REMOTE_HOST": REMOTE_HOST,
        "REMOTE_PORT": REMOTE_PORT
    })

    server = await asyncio.start_server(
        handle_socks_client, LOCAL_HOST, LOCAL_PORT
    )
    print(f"SOCKS5 proxy listening on {LOCAL_HOST}:{LOCAL_PORT}")
    print(f"Expecting a remote server on {REMOTE_HOST}:{REMOTE_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...")
