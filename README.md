# What is it
It's a *very simple* and *aspirationally lightweight* encrypted proxy ~~made complicated~~ to traffic traffic past RosComNadzor. Mostly inspired by ShadowSocks
### Installation
- Download the source (right now, downloading only the .py is good enough)
- Install requirements (pip install -r requirements.txt)
- Launch with python (python ./client.py)
- If it screams at you profanely, install the libraries i forgot to include
- If not, Ctrl-C
- Launch with correct server configuration (There is an option to save config, and later use it with -l option)
- Connect your browser\whatevers to localhost:1080
- Enjoy
- Optionally: build with nuitka or something
### How the protocol works:
- Client receives SOCKS5 handshake
- Client opens sockets and sends IP\:PORT..IVc2s..IVs2c to server (.. is concatination)
- Server opens sockets and starts relaying packets
- Packet structure: N bits of length, M bits of data (ChaCha20Poly1305 from cryptography module)
### Advantages:
- Almost headerless (The data is just length and encrypted bytes + mac)
- Fast enough (On my CPU, CURL can do ~350M)
- Works (i am surprised too)
### Is it good?
No.
### Future plans:
- Add obfuscation
- Make it more headerless
- Figure out some faster encryption
- Add options to change encryption
- Make code bearable to read
- Improve server-side to use command-line arguments
