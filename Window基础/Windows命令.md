# Windows命令

&nbsp;

## windows目录结构

### 【文件目录结构】
* C盘，最重要为c:\windows\system32
system32为计算机配置文件，cmd等重要文件所在文件夹

* Hosts文件c:\windows\system32\drivers\etc\hosts

* 创建用户登录后，在用户目录中会创建个人目录（这个目录无法删除，所以一般克隆window原有用户进行登录）

* program file(x86)：则计算机为64位，不是64位不会有该目录

* 隐藏文件夹programData，一些应用配置在这里，会开机自启，病毒会优先感染这里

### 【文件目录命令】

* copy con c:\123.txt 创建文件，开启后会开启用户交互界面，ctrl+z保存，命令行中不适用
* md abc 创建目录
* rd abc 删除文件夹
* ren 原文件名 新文件名
* del 删除文件

&nbsp;

## windows基础

### 【服务GUI】

* win+R  services.msc开启服务管理

### 【服务命令】

* net start 查看开启的服务
* sc config "服务名" start=disable 开机禁用
* sc config "服务名" start=auto 开机自动启动

### 【系统命令】

* systeminfo 查看系统补丁，正常系统含有300+补丁
* shutdown -r -t 0   -r重启，-s关机，-t延期时间

### 【应用管理】

* tasklist 查看进程，是否有防护软件
* taskkill 杀死进程
* wmic product get name,version 查看目标机安装的程序

&nbsp;

## windows网络

### 【网络命令】
* ipconfig /release释放ip地址
* ipconfig /renew重新获取ip地址
* netstat -an 查看网络连接
* start www.baidu.com 开启浏览器打开网址
* net use k: \\192.168.2.200:c:$  连接远程文件夹，在本地挂载为k盘
* net share查看共享
* net share c$ /del 删除c盘共享
* tracert 追踪路由


&nbsp;


## windows用户管理

### 【用户管理命令】

* net localgroup administrators 查看管理员组中的用户
* net user guest 查看访客用户
* net user guest 123.com设置guest用户密码
* net localgroup administrators guest /add 将guest用户加入管理员组
* net password 123.com  更改系统登录密码



## windows端口

* 端口复用情形：已经攻陷服务器，开启了3389，但是防火墙不让服务器出网，此时可以使用端口复用，需要上传端口复用的程序
或者使用http隧道，上传http隧道程序连接

