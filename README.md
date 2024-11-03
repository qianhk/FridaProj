## python

python -m venv .env
source .env/bin/activate
deactivate

pip install --upgrade frida
pip install --upgrade frida-tools

pip install frida-tools=a.b.c
pip install frida==x.y.z

独立环境安装全局python工具,互相依赖隔离
pipx install xxx
pipx uninstall package_name

## frida
frida-ls ls目录
frida-ls-devices ls设备

-U 连USB设备
-a 运行中的进程

frida-ps -U -a | grep Gadget
frida-trace -U Gadget -m "*[*ViewController viewDidLoad]"

frida-trace -U -p 52362 -m "-[ZaTestListViewController viewDidLoad]"

连iPhone上进程
frida -U -f njnu.kai.KaiDemo -l frida-agent-ts/_agent.js

## objection Runtime Mobile Exploration
pip3 install objection

https://github.com/sensepost/objection

objection操作
https://mabin004.github.io/2020/08/13/objection%E6%93%8D%E4%BD%9C/

正常启动：
objection -g com.xxx.xxx explore
指定ip和端口（与frida-server一致）
objection -N -h 192.168.1.221 -p 9999 -g com.xxx.xxx explore


https://github.com/sensepost/objection

git clone https://github.com/Tyilo/insert_dylib && cd insert_dylib &&xcodebuild && cp build/Release/insert_dylib /usr/local/bin/insert_dylib
git@github.com:tyilo/insert_dylib.git

objection patchipa -V 16.5.6 -s xxx.ipa -c 'Codesigning Identity to use'
security find-identity -p codesigning -v 可以看-c参数要的证书identity字符串

objection -g cn.xxxxx explore

### command
env
ls cd 
frida版本等信息
memory list modules
memory list exports libssl.so
memory list exports Xxx --json exports.json

object的命令执行结果是无法grep的，可以使用objection run xxx | grep yyy的方式，如（会导致explore中的命令退出，因为看起来重启app了）
objection -g cn.x.iphone.KaiDemo run memory list modules | grep c++
objection -g cn.x.iphone.KaiDemo run memory list exports KaiDemo

命令是memory dump all from_base，这部分内容与下文脱壳部分有重叠，我们在脱壳部分介绍用法。

memory dump all /tmp/dump dump所有内存
比较大，如1.8G。
memory dump from_base 指定地址和大小dump内存


搜索整个内存
命令是memory search --string --offsets-only，这部分也与下文脱壳部分有重叠，我们在脱壳部分详细介绍用法。

实用FRIDA进阶：内存漫游、hook anywhere、抓包
https://www.anquanke.com/post/id/197657

ios bundles list_bundles
ios bundles list_frameworks
ios cookies get

ios hooking list classes NSFileManager
ios hooking list class_methods NSFileManager
ios hooking generate xx

ios hooking watch class NSFileManager

jobs list
jobs kill 470100

