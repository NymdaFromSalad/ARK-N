# relay_server.py
import asyncio
from socket import gaierror


async def handle_client(reader, writer):
    line = await reader.readline()
    line = line.decode().strip()
    if not line:
        writer.close()
        return

    # For IPv6 addresses in brackets, e.g. [::1]:80, handle carefully:
    if line.startswith('['):
        # Format like: [IPv6]:port
        host_port_split = line.rsplit(']:', 1)
        if len(host_port_split) != 2:
            writer.close()
            return
        host = host_port_split[0][1:]  # remove starting '['
        port = int(host_port_split[1])
    else:
        # split on last colon
        if ':' not in line:
            writer.close()
            return
        host, port_str = line.rsplit(':', 1)
        port = int(port_str)

    print(f"Connecting to {host}:{port}")

    try:
        (
            remote_reader, remote_writer
        ) = await asyncio.open_connection(host, port)

        async def pipe(r, w):
            try:
                while True:
                    data = await r.read(4096)
                    if not data:
                        break
                    w.write(data)
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
            pipe(reader, remote_writer),
            pipe(remote_reader, writer)
        )
    except gaierror:
        print(f"Name not resolved: {host}")
        writer.close()
    except Exception as e:
        print("Connection error:", e, type(e))
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
