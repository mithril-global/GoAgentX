#!/bin/sh
GOAGENT_URL="https://nodeload.github.com/goagent/goagent/legacy.zip/3.0"

if [ "$GOAGENT_BUNDLE_PATH" == "" ]; then
    echo Missing bundle path
    exit 1
fi
if [ "$SERVICES_FOLDER" == "" ]; then
    SERVICES_FOLDER="$GOAGENT_BUNDLE_PATH/Contents/Resources/bin/"
fi


clean() {
    rm -rf $1/server/php
    rm $1/server/uploader.bat
    rm $1/server/uploader.zip
    rm $1/server/uploader.exe

    rm -rf $1/local/certs
    rm $1/local/CA.crt
    rm $1/local/cacert.pem
    rm $1/local/SwitchyOptions.bak
    rm $1/local/SwitchySharp_1_9_52.crx
    rm $1/local/addto-startup.py
    rm $1/local/addto-startup.vbs
    rm $1/local/addto-startup.js
    rm $1/local/goagent-gtk.py
    rm $1/local/goagent.exe
    rm $1/local/goagent-osx.command
    rm $1/local/msvcr100.dll
    rm $1/local/msvcr90.dll
    rm $1/local/_memimporter.pyd
    rm $1/local/SwitchySharp.crx
    rm $1/local/Microsoft.VC90.CRT.manifest
    rm $1/local/uvent.bat
    rm $1/local/proxy.bat
    rm $1/local/python33.*
    rm $1/local/python27.*
}

TMP_DIR=`mktemp -d -t goagent`
cd $TMP_DIR

echo 开始更新 goagent ...
echo 正在下载 goagent ...
if [ ! -f "./goagent.zip" ]; then
	curl -L -o goagent.zip $GOAGENT_URL
fi

echo 解压 goagent.zip ...
unzip goagent.zip
rm goagent.zip

goagent_folder=`ls | grep -m 1 goagent-`
goagent_folder=./$goagent_folder

echo goagent folder: $goagent_folder
echo bin folder: $SERVICES_FOLDER

if [ "$goagent_folder" != "./" ]; then
    clean $goagent_folder > /dev/null 2>&1
	cp -r $goagent_folder/* "$SERVICES_FOLDER"
fi

# 输出结果
echo 
echo goagent 更新完成.
echo goagent 客户端代码版本：
grep -m 1 __version__ $goagent_folder/local/proxy.py
echo goagent 服务端代码版本：
grep -m 1 __version__ $goagent_folder/server/gae/gae.py

# 删除临时文件
rm -r $TMP_DIR
