# web应用信息收集

&nbsp;

## web应用信息收集工具

### 【nmap收集web指纹】

* **使用nse脚本枚举80端口**
  ```bash
  sudo nmap -p80 --script=http-enum 192.168.2.200
  ```
  
### 【gobuster目录爆破】

* **gobuster目录爆破**
  ```bash
  gobuster dir -u http://192.168.2.100 -w /usr/share/wordlist/abc.lst
  ```
  对目标服务器发起目录爆破
  >在执行目录爆破时，相当于执行CC攻击，如果被ban，有以下解决方案：减小并发量，改为爬虫白名单（修改http头）

&nbsp;

## web应用枚举

### 【HTTP请求头和响应头】

>在许多默认配置中，响应头中还显示版本号。
响应头中的名称或值通常会显示有关应用程序所使用的技术栈的附加信息。

* **HTTP请求**
  * 请求行：
    一个HTTP请求由四个部分组成：请求行、请求头部、空行、请求数据，比如 GET /data/info.html HTTP/1.1
  * 请求头：
    HTTP客户程序(例如浏览器)，向服务器发送请求的时候必须指明请求类型(一般是GET或者 POST)。如有必要，客户程序还可以选择发送其他的请求头。大多数请求头并不是必需的，但Content-Length除外。对于POST请求来说 Content-Length必须出现。
    **Accept**： 浏览器可接受的MIME类型。
    **Accept-Charset**：浏览器可接受的字符集。
    **Accept-Encoding**：浏览器能够进行解码的数据编码方式。
    **Accept-Language**：浏览器所希望的语言种类。
    **Authorization**：授权信息，通常出现在对服务器发送的WWW-Authenticate头的应答中。
    **Content-Length**：表示请求消息正文的长度。
    **Host**： 客户机通过这个头告诉服务器，想访问的主机名。
    **If-Modified-Since**：客户机通过这个头告诉服务器，资源的缓存时间。
    **Referer**：客户机通过这个头告诉服务器，它是从哪个资源来访问服务器的(防盗链)。
    **User-Agent**：User-Agent头域的内容包含发出请求的用户信息。
    **Cookie**：客户机通过这个头可以向服务器带数据，这是最重要的请求头信息之一。
    **Pragma**：指定“no-cache”值表示服务器必须返回一个刷新后的文档，即使它是代理服务器而且已经有了页面的本地拷贝。
    **From**：请求发送者的email地址，由一些特殊的Web客户程序使用，浏览器不会用到它。
    **Connection**：处理完这次请求后是否断开连接还是继续保持连接。
    **Range**：Range头域可以请求实体的一个或者多个子范围。
  
* **HTTP响应**
  * 响应行：
    响应行一般由协议版本、状态码及其描述组成 比如 HTTP/1.1 200 OK，其中协议版本HTTP/1.1或者HTTP/1.0，200就是它的状态码，OK则为它的描述。
    常见状态码：
    100~199：表示成功接收请求。
    200~299：表示成功接收请求并已完成整个处理过程。常用200
    300~399：为完成请求，客户需进一步细化请求。
    400~499：客户端的请求有错误。
    500~599：服务器端出现错误。
  * 响应头：
    **Allow**：服务器支持哪些请求方法(如GET、POST等)。
    **Content-Encoding**：文档的编码(Encode)方法。
    **Content-Length**：表示内容长度。
    **Content- Type**：表示后面的文档属于什么MIME类型。
    **Date**：当前的GMT时间。
    **Expires**：告诉浏览器把回送的资源缓存多长时间，-1或0则是不缓存。
    **Last-Modified**：文档的最后改动时间。
    **Location**：这个头配合302状态码使用，用于重定向接收者到一个新URI地址。
    **Refresh**：告诉浏览器隔多久刷新一次，以秒计。
    **Server**：服务器通过这个头告诉浏览器服务器的类型。
    **Set-Cookie**：设置和页面关联的Cookie。。
    **Transfer-Encoding**：告诉浏览器数据的传送格式。
    **WWW-Authenticate**：客户应该在Authorization头中提供什么类型的授权信息。
    >注：设置应答头最常用的方法是HttpServletResponse的setHeader，该方法有两个参数，分别表示应答头的名字和值。和设置状态代码相似，设置应答头应该在发送任何文档内容之前进行。
    
    **setContentType**：设置Content-Type头。
    **setContentLength**：设置Content-Length头。
    **addCookie**：设置一个Cookie
  
### 【HTTP安全头，SSL/TLS】

* **Strict-Transport-Security (HSTS)**
  它告诉浏览器只能通过HTTPS访问当前资源，而不是 HTTP。
  ```
  strict-transport-security: max-age=31536000; includeSubDomains; preload
  ```
  
  * max-age=<expire-time> 设置在浏览器收到这个请求后的 秒的时间内凡是访问这个域名下的请求都使用 HTTPS 请求。
  * includeSubDomains 可选，如果这个可选的参数被指定，那么说明此规则也适用于该网站的所有子域名。
  * preload 可选，加入预加载列表

* **Public-Key-Pins（HPKP）**
  防止中间人攻击。是 HTTPS 网站防止攻击者利用 CA 错误签发的证书进行中间人攻击的一种安全机制，用于预防 CA 遭入侵或者其他会造成 CA 签发未授权证书的情况。服务器通过 Public-Key-Pins（或 Public-Key-Pins-Report-Onky 用于监测）header 向浏览器传递 HTTP 公钥固定信息。
  ```
  Public-Key-Pins: pin-sha256="base64=="; max-age=expireTime [; includeSubdomains][; report-uri="reportURI"]
  ```
  
  * pin-sha256：即证书指纹，允许出现多次，实际上应用最少指定两个
  * max-age：过期时间
  * includeSubdomains：是否包含子域
  * report-uri：验证失败时上报的地址

* **Content-Security-Policy（CSP）**
  CSP 是一个计算机的安全标志，主要用来防止 XSS、点击劫持、SQL 注入等攻击；CSP 通过定义运行加载脚本的位置和内容防止恶意代码的加载。
  ```
  Content-Security-Policy: default-src 'self'
  ```
  
  * default-src 是 CSP 指令，多个指令之间使用英文分号分割。self即允许同源资源加载

* ** Referrer-Policy**
  用来监管哪些访问来源信息——会在 Referer 中发送——应该被包含在生成的请求当中。
  ```
  Referrer-Policy: no-referrer
  Referrer-Policy: no-referrer-when-downgrade
  Referrer-Policy: origin
  Referrer-Policy: origin-when-cross-origin
  Referrer-Policy: same-origin
  Referrer-Policy: strict-origin
  Referrer-Policy: strict-origin-when-cross-origin
  Referrer-Policy: unsafe-url
  ```
  
  * no-referrer：不允许被记录。
  * origin：只记录 origin，即域名。
  * strict-origin：只有在 HTTPS -> HTTPS 之间才会被记录下来。
  * strict-origin-when-cross-origin：同源请求会发送完整的 URL；HTTPS->HTTPS，发送源；降级下不发送此首部。
  * no-referrer-when-downgrade(default)：同 strict-origin。
  * origin-when-cross-origin：对于同源的请求，会发送完整的 URL 作为引用地址，但是对于非同源请求仅发送文件的源。
  * same-origin：对于同源请求会发送完整 URL，非同源请求则不发送 referer。
  * unsafe-url：无论是同源请求还是非同源请求，都发送完整的 URL（移除参数信息之后）作为引用地址。

* **Expect-CT**
  Expect-CT 头允许站点选择性报告和/或执行证书透明度 (Certificate Transparency) 要求，来防止错误签发的网站证书的使用不被察觉。当站点启用 Expect-CT 头，就是在请求浏览器检查该网站的任何证书是否出现在公共证书透明度日志之中。
  ```
  Expect-CT: report-uri="<uri>";
           enforce;
           max-age=<age>
  ```
  
  * max-age,该指令指定接收到 Expect-CT 头后的秒数，在此期间用户代理应将收到消息的主机视为已知的 Expect-CT 主机。
  * report-uri="" 可选,该指令指定用户代理应向其报告 Expect-CT 失效的 URI。
  * enforce 可选,该指令示意用户代理应强制遵守证书透明度政策（而不是只报告合规性），并且用户代理应拒绝违反证书透明度政策的之后连接。


* **Access-Control-Allow-Origin**
  Access-Control-Allow-Origin 响应头指定了该响应的资源是否被允许与给定的origin共享。跨原始资源共享（CORS）允许网站在它们之间共享内容，为了使网站之间安全的跨域获取资源，可以通过设置Access-Control-Allow-Origin来允许指定网站来跨域获取本地资源。
  ```
  Access-Control-Allow-Origin: http://10.10.10.10
  ```
  
* **Cache-Control**
  Cache-Control 通用消息头字段，被用于在 http 请求和响应中，通过指定指令来实现缓存机制。缓存指令是单向的，这意味着在请求中设置的指令，不一定被包含在响应中。
  
* **Set-Cookie**
  由服务器端向客户端发送 cookie
  ```
  Set-Cookie: <cookie-name>=<cookie-value>
  Set-Cookie: <cookie-name>=<cookie-value>; Expires=<date>
  Set-Cookie: <cookie-name>=<cookie-value>; Max-Age=<non-zero-digit>
  Set-Cookie: <cookie-name>=<cookie-value>; Domain=<domain-value>
  Set-Cookie: <cookie-name>=<cookie-value>; Path=<path-value>
  Set-Cookie: <cookie-name>=<cookie-value>; Secure
  Set-Cookie: <cookie-name>=<cookie-value>; HttpOnly
  
  Set-Cookie: <cookie-name>=<cookie-value>; SameSite=Strict
  Set-Cookie: <cookie-name>=<cookie-value>; SameSite=Lax
  
  // Multiple directives are also possible, for example:
  Set-Cookie: <cookie-name>=<cookie-value>; Domain=<domain-value>; Secure; HttpOnly
  ```
  
  * HttpOnly：防止使用 javascript（如 document.cookie）去存取 cookie


* **X-Frame-Options**
  是否允许一个页面可在 < frame >、< iframe >、< embed > 或者 < object > 中展现的标记。
  ```
  X-Frame-Options: DENY
  X-Frame-Options: SAMEORIGIN
  X-Frame-Options: ALLOW-FROM https://example.com/
  ```
  
* **X-XSS-Protection**
  HTTP X-XSS-Protection 响应头是 Internet Explorer，Chrome 和 Safari 的一个特性，当检测到跨站脚本攻击 (XSS)时，浏览器将停止加载页面。若网站设置了良好的 Content-Security-Policy 来禁用内联 JavaScript ('unsafe-inline')，现代浏览器不太需要这些保护， 但其仍然可以为尚不支持 CSP 的旧版浏览器的用户提供保护。
  ```
  X-XSS-Protection: 0
  X-XSS-Protection: 1
  X-XSS-Protection: 1; mode=block
  X-XSS-Protection: 1; report=<reporting-uri>
  ```
  
  * 0：禁止XSS过滤。
  * 1：启用XSS过滤（通常浏览器是默认的）。 如果检测到跨站脚本攻击，浏览器将清除页面（删除不安全的部分）。
  * 1; mode=block：启用 XSS 过滤。 如果检测到攻击，浏览器将不会清除页面，而是阻止页面加载。
  * 1; report= (Chromium only)：启用 XSS 过滤。 如果检测到跨站脚本攻击，浏览器将清除页面并使用 CSP report-uri指令的功能发送违规报告。


* **X-Content-Type-Options**
  X-Content-Type-Options HTTP 消息头相当于一个提示标志，被服务器用来提示客户端一定要遵循在 Content-Type 首部中对 MIME 类型 的设定，而不能对其进行修改。这就禁用了客户端的 MIME 类型嗅探行为。
  
  ```
  X-Content-Type-Options: nosniff
  ```
  
* **X-Permitted-Cross-Domain-Policies**
  用于指定客户端能够访问的跨域策略文件的类型。
  ```
  X-Permitted-Cross-Domain-Policies: none
  X-Permitted-Cross-Domain-Policies: master-only
  X-Permitted-Cross-Domain-Policies: by-content-type
  X-Permitted-Cross-Domain-Policies: by-ftp-filename
  X-Permitted-Cross-Domain-Policies: all
  ```
  
  * none：目标服务器的任何位置都不允许使用策略文件，包括主策略文件
  * master-only：仅允许使用主策略文件
  * by-content-type：仅限 HTTP/HTTPS 协议使用，只允许使用 Content-Type: text/x-cross-domain-policy 提供的策略文件
  * by-ftp-filename：仅限 FTP 协议使用，只允许使用文件名为 crossdomain.xml 的策略文件
  * all：目标域上的所有策略文件都可以使用


* **Permissions-Policy（Feature-Policy）**
  Feature Policy 是一个新的 http 响应头属性，允许一个站点开启或者禁止一些浏览器属性和 API，来更好的确保站点的安全性和隐私性。有点类似内容安全策略，但是它控制的是浏览器的特征而不是安全行为.
  ```
  Feature-Policy: <feature> <allowlist>
  Feature-Policy: vibrate 'self'; usermedia '*'; sync-xhr 'self' example.com
  ```
  

### 【枚举web应用API】

在许多情况下，我们的渗透测试目标是一个内部构建的闭源web应用程序，它附带了许多应用程序编程接口，即API

* **API类型**
  一般API入口会是功能名称加上版本号组成
  例如：.../books/v1    .../user_change/v2   等等

* **使用gobuster爆破API入口**
  
  * 使用gobuster模式爆破，-p参数
  * 创建模式文件，pattern.txt，其中写入匹配语句：{GOBUSTER}/v1    {GOBUSTER}/v2，GOBUSTER将转化为字典中的条目，后面版本号不止v1v2，可以写很多
  * 为了验证是否有任何API属性与username属性相关，我们将通过在最后插入admin用户名来扩展API路径。..../user/v1/admin
  * 有时发现register API，可以尝试注册新用户为admin用户，其中写入admin=true值，如果成功则创建了一个管理员用户，使用该账户可以修改admin用户密码


### 【Token】

* **JWT Token**
  json web token全称

  * JWT编码后样子：eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
  eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
  UQmqAUhUrpDVV2ST7mZKyLTomVfg7sYkEjmdDI5XF8Q

  * JWT由三部分组成：
    **header** 其中含有声明类型，加密算法所有内容经过base64加密后的密文
    **playload** 存放有效信息位置，包括标准注册声明，公共声明，私有声明
    **signature** 这个部分需要base64加密后的header和base64加密后的payload使用.连接组成的字符串(头部在前)，然后通过header中声明的加密方式进行加盐secret组合加密，然后就构成了jwt的第三部分。
  
  * JWT token会在请求头中，Authorization：.....

* **Wordpress nonce Token**
  * WordPress的Nonce用来保护URL和表单免受恶意攻击。它帮助WordPress确定一个请求是否有效，防止未经授权的行动和输入。

  * Nonces通过给URL增加一个额外的保护层来防止CSRF攻击。例如在url中嵌入wpnonce字段
  ```
  http://yourwebsite.com/wp-admin/post.php?post=123&action=trash&_wpnonce=b192fc4204
  ```
  
  * 如果你在没有WordPress生成的正确的nonce的情况下试图进入该URL，你会看到一个403 Forbidden。
  * Nonce的默认寿命是24小时

