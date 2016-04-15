# GoAgentX

This is an unofficial distribution of GoAgentX 2.x with (somehow) updated dependencies.

非官方GoAgentX 2.x 发行版

GoAgentX is an almighty proxy client and process manager for Mac OS X.

GoAgentX currently supports:  
现支持如下协议：

- shadowsocks
- cow
- GoAgent
- SSH Tunnel
- Stunnel
- SPDY Proxy

You can also add support for other proxy services easily.

# Screenshot

![screenshot](https://github.com/mithril-global/GoAgentX/raw/master/screenshot.png)

# Download

Clone the repository or download master branch as [zip](https://github.com/mithril-global/GoAgentX/archive/master.zip)

# Install

Drag `GoAgentX.app` to your Applications folder.

# How to update ss-local

First install ss-local using Homebrew.

Then copy `/usr/local/Cellar/shadowsocks-libev/<VERSION>/bin/ss-local` and `/usr/local/Cellar/openssl/1.0.2g/lib/libcrypto.1.0.0.dylib` to `GoAgentX.app/Contents/PlugIns/shadowsocks.gxbundle/Contents/Resources/bin/libev/`.

In `GoAgentX.app/Contents/PlugIns/shadowsocks.gxbundle/Contents/Resources/bin/libev/`, run the command `install_name_tool -change /usr/local/opt/openssl/lib/libcrypto.1.0.0.dylib @executable_path/libcrypto.1.0.0.dylib -id libcrypto.1.0.0.dylib ss-local`.

Now enjoy :)

# Acknowledgement

All binaries are from their corresponding upstream.

# Disclaimer

Use at your own risk.
