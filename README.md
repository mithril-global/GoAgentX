# GoAgentX

This is an unofficial distribution of GoAgentX 2.x with (somehow) updated dependencies.

非官方GoAgentX 2.x 发行版，SS及COW已经更新到最新。测试兼容 El Capitan 与 High Sierra 。

GoAgentX is an almighty proxy client and process manager for Mac OS X.

GoAgentX currently supports:  
现支持如下协议：

- shadowsocks
- shadowsocksR
- cow
- GoAgent
- SSH Tunnel
- Stunnel
- SPDY Proxy

You can also add support for other proxy services easily.

# Note for Sierra users

若提示“包已损坏”，请：

### Method 1:

右键->打开

### Method 2:

1. 打开终端输入如下命令：`sudo spctl --master-disable`并键入您的密码（解除完整性检查）。
2. 再次双击打开程序包。
3. 终端输入`sudo spctl --master-enable`并键入密码（重新启用完整性检查）。

# Screenshot

![screenshot](https://github.com/mithril-global/GoAgentX/raw/master/screenshot.png)

# Download

Clone the repository or download master branch as [zip](https://github.com/mithril-global/GoAgentX/archive/master.zip)

# Install

Drag `GoAgentX.app` to your Applications folder.

# CHANGELOG

- 2018/1/29 Updated shadowsocksR for all platforms, options should be put in the "Advanced Config Template" section
- 2017/10/12 Updated COW for High Sierra, now using MEOW 1.5 instead
- 2016/12/1 Added docs on "Package damaged" on Sierra
- 2016/7/1 Supports chacha20 (Now you can choose in the drop-down)
- 2016/4/13 Updated shadowsocks-libev to 2.4.5, cow to 0.9.6

# How to update ss-local

First install ss-local using Homebrew.

Then copy `/usr/local/Cellar/shadowsocks-libev/<VERSION>/bin/ss-local` and `/usr/local/Cellar/openssl/1.0.2g/lib/libcrypto.1.0.0.dylib` to `GoAgentX.app/Contents/PlugIns/shadowsocks.gxbundle/Contents/Resources/bin/libev/`.

In `GoAgentX.app/Contents/PlugIns/shadowsocks.gxbundle/Contents/Resources/bin/libev/`, run the command `install_name_tool -change /usr/local/opt/openssl/lib/libcrypto.1.0.0.dylib @executable_path/libcrypto.1.0.0.dylib -id libcrypto.1.0.0.dylib ss-local`.

Now enjoy :)

# Acknowledgement

All binaries are from their corresponding upstream.

For obvious reasons, please see the credits inside the About section in the downloaded application.

# Disclaimer

Use at your own risk.
