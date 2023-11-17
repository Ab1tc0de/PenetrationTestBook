# Linux命令

&nbsp;

## 文件和目录

* ```bash
  ls -F
  ```
  在没有颜色突出的系统中显示出目录

* ```bash
  ls -R
  ```
  -R为递归选项，会输出目录中的目录和文件

* ```bash
  ls -l scr*
  ```
  可以使用通配符搜索

* ```bash
  ln -s datafile sl_datafile
  ```
  创建sl_datafile指向datafile的软连接

* ```bash
  mkdir -p test1/test2/test3
  ```
  使用-p参数创建嵌套目录

* ```bash
  tree
  ```
  显示当前目录的目录树
  ```bash
   tree dirbase  /tree -hf 
  ```
  -h显示文件夹内的内容大小，-f显示文件完整路径

* ```bash
  file my_file
  ```
  查看文件类型

* ```bash
  cat -n test1.sh
  ```
  显示test1文件并且标记行号

* ```bash
  ls -li /etc/hosts
  ```
  查看文件indode节点

* ```bash
  chattr +i /etc/hosts
  ```
  给文件加上indode节点，锁定文件

* ```bash
  chattr -i /etc/hosts
  ```
  取消锁定

* ```bash
  lsattr /etc/hosts
  ```
  查看文件隐藏属性
  

&nbsp;

## 系统监测

* ```bash
  ps aux/ps -ef
  ```
  查看所有进程，包括后台进程

* ```bash
  ps aux | grep 目标程序
  ```

* ```bash
  pstree 查看进程树
  ```
  -p可以查看进程id

* 进入top时，输入M（以内存占用排序），P（按cpu占用排序），k  （杀死进程，）输入k时，会要求输入PID值，然后是信号值，15或9（9为强制结束）


* ```bash
  kill -s 信号值/信号名 3454
  ```
  使用进程id结束进程

* ```bash
  killall 进程名
  ```
  结束进程树

* ```bash
  top -c -o %CPU
  ```
  查看cpu占用，-c显示命令行参数，-o按照指定字段排序

* ```bash
  ps -eo pid,ppid,%mem,%cpu,cmd --sort=-%cpu | head -n 5
  ```
  查看cpu占用前5的进程
  

&nbsp;

## 用户组的管理

* ```
  sudo授权文件/etc/sudoers
  %sudo ALL(ALL) ALL
  ```
  用户（被授权的用户或组） 主机名列表=（用户） 命令程序列表

* ```bash
  useradd -m -G sudo -s /bin/bash abc 
  ```
  useradd -m 创建用户家目录 -G 组名称 -s 指定用户登录的shell

* ```bash
  usermod -p ‘hash加密的密文’ 用户名
  ```
  修改用户密码

* ```bash
  openssl passwd -1 -salt 用户名 密码
  ```
  使用openssl的passwd哈希密码加密功能，加密用户密码，-1 是使用MD5加密

* ```bash
  passwd 用户名 密码
  ```
  设置用户密码，限于已存在用户并且密码为加密密文

* ```bash
  userdel 用户名 （删除 用户）/userdel -rf 用户名
  ```
  -r删除用户家目录，-f强制删除用户无论是否已经登录

* ```bash
  who /w
  ```
  查看在线用户

* ```bash
  last
  ```
  查看用户最近登录信息
  

&nbsp;

## Linux硬件信息

* ```bash
  uname -a
  ```
  查看版本信息

* ```bash
  cat /etc/issue
  ```
  本地控制台标题信息

* ```bash
  lsb_release -a
  ```
  查看发行版本

* ```bash
  cat /proc/cpuinfo | more
  ```
  查看cpu型号

* ```bash
  cat /proc/meminfo 
  ```
  查看内存

* ```bash
  free -m
  ```
  查看内存，以M为单位

* ```bash
  fdisk -l 
  ```
  （显示所有硬盘）1-4保留给主分区，扩展分区也占用一个，逻辑分区从5开始

* ```bash
  lsblk
  ```
  显示块设备

* ```bash
  lsusb
  ```
  显示usb设备
  

&nbsp;

## 网络管理

* ```bash
  netstat -antu
  ```
  -a显示所有网络连接，-n以数字形式不做名称解析，-t查看tcp连接，-u查看udp连接

* ```bash
  systemctl start ssh /systemctl stop ssh /systemctl status ssh /systemctl restart ssh
  ```
  开启，关闭，查看，重启ssh服务

* ```bash
  systemctl is-enable ssh
  ```
  查看ssh服务是否开机启动

* ```bash
  systemctl enable ssh
  ```
  设置ssh服务开机启动

* 完成域名解析/etc/hosts（优先级比DNS高）
  格式：
  IP地址      主机名1  主机名2 ......
  作用：加快访问站点的速度，屏蔽一些站点，帮助做实验


* ```bash
  service --status-all
  ```
  查看本机所有服务

&nbsp;

## 压缩文件

* ```bash
  tar -cf document.tar /home/work
  ```
  将work文件夹压缩为document.tar文件，-c 是表示产生新的包，-f 指定包的文件名。
  
* ```bash
  tar -xf document.tar
  ```
  将document.tar文件解压到当前目录，-x 是解开的意思。
  
* ```bash
  tar -czf abc.tar.gz /home/work
  ```
  -z 指定tar.gz压缩文件，将work压缩为abc.tar.gz文件
  
* ```bash
  tar -xzf abc.tar.gz
  ```
  将abc.tar.gz解压到当前目录
  
* ```bash
  tar -cjf all.tar.bz2 *.jpg
  ```
  -j 代表bzip2压缩文件
  
* ```bash
  tar -xjf all.tar.bz2
  ```
  
* ```bash
  zip -q -r abc.zip /home/work
  ```
  -q 不显示执行过程 -r 递归处理
  
* ```bash
  unzip abc.zip -d /home/work
  ```
  将abc.zip解压到work目录中