# arpscanf 使用arp原理对局域进扫描，都是毫秒级别，使用协程提高扫描效率，基本是秒出
编译：
```sh
git clone https://github.com/findnr/arpscanf.git
gcc -o arpscanf arpscanf.c -Wall
```
最后生成一个要执行文件arpscanf,注意执行要使用root权限
```sh
./arpscanf eth0 192.168.1.88 24
```

