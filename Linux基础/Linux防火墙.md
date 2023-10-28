# Linux防火墙



## iptables防火墙

iptables 是集成在 Linux 内核中的包过滤防火墙系统。使用 iptables 可以添加、删除具体的过滤规则，iptables 默认维护着 4 个表和 5 个链，所有的防火墙策略规则都被分别写入这些表与链中。

“四表”是指 iptables 的功能，默认的 iptable s规则表有 filter 表（过滤规则表）、nat 表（地址转换规则表）、mangle（修改数据标记位规则表）、raw（跟踪数据表规则表）

“五链”是指内核中控制网络的 NetFilter 定义的 5 个规则链。每个规则表中包含多个数据链：INPUT（入站数据过滤）、OUTPUT（出站数据过滤）、FORWARD（转发数据过滤）、PREROUTING（路由前过滤）和POSTROUTING（路由后过滤），防火墙规则需要写入到这些具体的数据链中。

### 【iptables使用方法】

```bash
> iptables [-t table] COMMAND [chain] CRETIRIA -j ACTION
```
* -t：指定需要维护的防火墙规则表 filter、nat、mangle或raw。在不使用 -t 时则默认使用 filter 表。
* COMMAND：子命令，定义对规则的管理。
* chain：指明链表。
* CRETIRIA：匹配参数。
* ACTION：触发动作。

### 【iptables增删改查】

* **查看规则**
  ```bash
  iptables -nvL
  ```
  -n不对地址反查，-L查看所有规则，默认查看filter表，-v详细信息
  ```bash
  iptables -nL --line-number
  ```
  --line-number 显示规则列表顺序
  
* **添加规则**
  ```bash
  iptables -A INPUT -s 192.168.2.29 -j DROP
  ```
  
* **修改规则**
  ```bash
  iptables -R INPUT 4 -s 192.168.2.1 -j ACCEPT
  ```
  
* **删除规则**
  ```bash
  iptables -D OUTPUT 5
  ```

* **清空防火墙数据表信息**
  ```bash
  iptables -Z
  ```
  
* **备份防火墙数据**
  ```bash
  iptables-save > ./iptables/runles
  ```
  

&nbsp;

