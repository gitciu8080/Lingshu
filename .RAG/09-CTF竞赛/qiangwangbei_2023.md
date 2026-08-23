# 强网杯 2023 攻击 Agent 知识库
> 关键词:强网杯2023,Writeup,攻击Agent,攻击链,CTF,PWN,Web,逆向,Misc,密码

> 来源：星盟安全团队《强网杯2023-Writeup》，页面日期 2023-12-18。
> 原始 HTML：`强网杯2023-Writeup - 星盟安全团队.html`
>
> 本文档是面向 CTF、靶场和明确授权安全测试环境的 Agent 知识库版本。
> 内容严格以原 Writeup 为基础，并将题解抽象为“识别特征 → 漏洞/算法 → 利用原语 → 下一步动作”。
>
> **注意**：原文中的远程地址、临时 Token、反弹 Shell 地址等不作为知识库固定目标；统一视为历史题目环境，Agent 应替换为当前授权环境参数。

---

## 0. 知识库元数据

```yaml
name: qiangwangbei_2023
event: 强网杯2023
source: 星盟安全团队
date: 2023-12-18
purpose: attack-agent-rag
categories:
  - Misc
  - 强网先锋
  - PWN
  - Crypto
  - Web
  - RE
```

原页面的目录包含 Misc、强网先锋、PWN、Crypto、Web、RE 六大部分。题目包括 `easyfuzz`、两个 Pyjail、`Hello Spring`、`Happy Chess`、`谍影重重`、`ez_fmt`、`石头剪刀布`、`tire`、多个逆向题、`WTOA`、`simpleinterpreter`、`chatting`、`warmup23`、`A-rtsp`、`not only rsa`、`happgame`、`thinkshop`、`ezre`、`dotdot` 等。fileciteturn3file0L15-L15

---

# 1. Agent 总体检索策略

攻击 Agent 遇到新题时，不应该只搜索“题目名称”，而应该搜索以下模式：

```text
输入处理
过滤器
模板
反序列化
格式化字符串
堆
double free
off-by-null
tcache
fastbin
RTSP
指针
ptrace
反调试
RC4
TEA-like
RSA p^5
ADS-B
Mode-S
取证
Trie
```

推荐决策链：

```text
目标识别
  ↓
输入/协议/文件格式识别
  ↓
漏洞或算法模式匹配
  ↓
建立利用原语
  ↓
信息泄露/地址计算/绕过
  ↓
控制流或数据流控制
  ↓
读取 flag / 完成题目目标
```

---

# 2. Misc

## 2.1 easyfuzz

### 原题特征

输入 `000000000` 后出现 `1` 的变化；继续输入包含 `qwb` 的字符串后发现特定字符组合会触发 `1` 回显。

原 Writeup 的思路是：

```text
000000000
  ↓
发现特殊回显
  ↓
尝试 qwb
  ↓
00qwbqwbq
  ↓
逐字符 Fuzz
  ↓
恢复密码
  ↓
00qwbGood
  ↓
获得 flag
```

### Agent 识别规则

如果程序：

- 输入长度固定或近似固定；
- 输出只有 0/1 等少量反馈；
- 某些字符/字符对导致反馈变化；
- 没有明显错误信息；

则应考虑：

```text
黑盒逐字符 Fuzz
差分反馈
字符集合枚举
状态机推断
```

### 标签

```text
fuzzing
black-box
oracle
字符枚举
差分反馈
```

---

## 2.2 Pyjail ! It’s myFILTER !!!

### 核心信息

原 Writeup 指出环境变量中存在 `flag`，可以通过读取 `/proc/self/environ` 获取。

核心思路：

```python
print(open("/proc/self/environ").read())
```

### Agent 规则

检测到 Python Jail 时：

```text
检查环境变量
检查 /proc/self/environ
检查 globals / locals
检查 __builtins__
检查可访问文件
检查对象属性链
```

### 标签

```text
pyjail
python-sandbox
environment-variable
procfs
information-disclosure
```

原文明确说明“环境变量有 flag”，并给出了 `/proc/self/environ` 读取方式。fileciteturn0file0L186-L187

---

## 2.3 Hello Spring

### 漏洞链

原 Writeup：

```text
Spring
 ↓
不出网
 ↓
LFI
 ↓
ClassPathXmlApplicationContext 被过滤
 ↓
拆分字符串绕过过滤
 ↓
构造 XML
 ↓
java.lang.ProcessBuilder
 ↓
命令执行
```

关键类：

```text
org.springframework.context.support.ClassPathXmlApplicationContext
java.lang.ProcessBuilder
```

原题使用模板环境加载 Spring 类，并将被过滤的类名拆成：

```text
"org.springframework.context." + "support.ClassPathXmlApplicationContext"
```

之后通过 `ClassPathXmlApplicationContext` 加载上传的 XML 配置。fileciteturn0file0L188-L218

### Agent 检测规则

发现：

```text
Spring
+
模板表达式
+
类名黑名单
+
LFI/文件加载
```

优先检查：

```text
字符串拼接绕过
反射
ClassLoader
Beans
ResourceLoader
XML Bean
ProcessBuilder
```

### 利用链抽象

```text
模板执行
 ↓
获得 Spring Bean
 ↓
ClassLoader
 ↓
动态加载被过滤类
 ↓
ClassPathXmlApplicationContext
 ↓
读取攻击者控制 XML
 ↓
ProcessBuilder
 ↓
命令执行
```

---

## 2.4 Happy Chess

原 Writeup 观察到：

```text
1 1
2 2
3 3
...
9 9
exit
```

能够出现 `success`，随后用脚本重复执行十轮。

### Agent 规则

如果交互式题目：

- 输入存在明显的成对字段；
- 每轮输入结构类似；
- 某个简单模式能够触发 success；
- 成功状态需要重复多轮；

则优先：

```text
建立状态机
记录每轮输入
寻找固定序列
自动循环
```

标签：

```text
state-machine
interactive
automation
repetition
```

---

## 2.5 问卷调查

原文只说明：

```text
完成问卷即可获得 flag
```

不包含进一步技术细节。

Agent 不应从该条目推断额外漏洞。

---

## 2.6 Pyjail ! It’s MyRevenge !!!

### 核心漏洞

原 Writeup 指出可以通过 `locals()` 修改当前上下文中的：

```text
my_filter
len
```

并利用 `input()` 获得下一轮输入。

### 利用链

```text
locals()
 ↓
修改过滤函数
 ↓
恢复 input 使用能力
 ↓
修改 len
 ↓
让过滤条件失效
 ↓
再次获得输入
 ↓
访问 __builtins__
 ↓
导入 os
 ↓
执行命令
```

原文给出的两个关键操作：

```python
{locals().update({"my_filter":len})}{{{"inp"+"ut()"}}}
```

```python
{locals().update({"len":lambda x:0})}{{{"inp"+"ut()"}}}
```

之后通过 `__builtins__.__import__("os")` 调用 `os.execv`。fileciteturn2file0L11-L18

### Agent 识别规则

遇到 Python 模板/Jail：

```text
locals
globals
eval
exec
input
filter
len
__builtins__
__import__
```

优先考虑：

```text
上下文污染
函数替换
过滤器覆盖
长度检查绕过
动态导入
```

---

## 2.7 谍影重重

### 协议识别

原 Writeup 判断为：

```text
Mode-S
ADS-B
```

存在两种数据：

```text
1a32 → Mode-S 短包
1a33 → Mode-S 长包
```

随后提取有效字段并批量解码。fileciteturn1file0L20-L24

最终按照 ICAO 值进行排序/筛选，正确答案为：

```text
79A05E
```

对应 flag：

```text
flag{4cf6729b9bc05686a79c1620b0b1967b}
```

fileciteturn3file9L224-L228

### Agent 规则

遇到网络流量取证：

```text
先识别协议
 ↓
识别短包/长包
 ↓
提取协议有效字段
 ↓
批量解码
 ↓
按照题目约束筛选
 ↓
验证结果
```

标签：

```text
pcap
ADS-B
Mode-S
ICAO
traffic-analysis
protocol-decoding
```

---

# 3. 强网先锋

## 3.1 ez_fmt

### 漏洞

格式化字符串漏洞。

原 Writeup 直接采用：

```text
格式化字符串
 ↓
泄露 libc
 ↓
计算 libc base
 ↓
修改目标地址
 ↓
one_gadget
 ↓
控制流劫持
```

原文脚本通过：

```text
%p
%hn
```

完成地址泄露和半字写，并根据泄露值计算 libc 基址。fileciteturn3file12L279-L285

### Agent 规则

发现：

```c
printf(user_input);
```

或者：

```c
printf(buf);
```

优先检查：

```text
%x
%p
%s
%n
%hn
%hhn
```

建立：

```text
栈泄露
 ↓
libc 泄露
 ↓
目标地址覆盖
 ↓
one_gadget / ROP
```

标签：

```text
format-string
fmtstr
leak
%hn
one_gadget
libc
```

---

## 3.2 石头剪刀布

### 漏洞模式

前 6 位随机，但从第 7 位开始存在模型缺陷。

Writeup 描述：

```text
从第七位开始
如果预测对方出石头
则下一位固定出布
```

因此可以记录每次获胜后的下一位模式，构造完整输入序列。

### Agent 规则

遇到：

```text
伪随机
游戏 AI
固定状态转移
前 N 次随机
后续行为可预测
```

应该：

```text
记录输入/输出序列
 ↓
寻找转移关系
 ↓
寻找周期
 ↓
确认第一个稳定状态
 ↓
生成自动化输入
```

标签：

```text
predictable-rng
state-machine
game-logic
model-flaw
```

---

## 3.3 tire

### 核心漏洞

题目使用二叉 Trie：

```text
IP 地址二进制值
 ↓
Trie 路径
 ↓
节点 index
 ↓
view
```

原 Writeup 指出：

- 最右边最低位作为根节点；
- 最左边作为叶子节点；
- 节点保存 index；
- 可以通过构造 IP 路径控制叶子节点 index；
- 当 index 达到 flag 所在区域时，`view` 可以读取 flag 地址。

### 利用抽象

```text
构造 0.0.0.0
+
构造 255.255.255.255
 ↓
控制最后节点 index
 ↓
view 255.255.255.255
 ↓
读取 flag 前若干字节

增加 128.0.0.0
 ↓
创建新叶子
 ↓
index + 1
 ↓
读取下一段 flag
```

### Agent 规则

发现：

```text
Trie
IP → binary
节点 index
view/read
```

检查：

```text
节点索引是否可控
节点是否存在越界
index 是否直接作为数组/地址使用
新增节点是否影响后续索引
```

标签：

```text
trie
binary-tree
index-confusion
out-of-bounds-read
arbitrary-read
IP-routing
```

---

## 3.4 ezre

### 核心

题目使用多张 Base64 表，并进行逆向编码/解码。

存在 init array 中的反调试检查，会破坏数据。

Writeup 采用：

```text
附加调试
 ↓
绕过反调试
 ↓
动态调试
 ↓
获取运行时表
 ↓
恢复数据
 ↓
CyberChef 解码
```

核心逆变换：

```c
a1[len] ^= a1[len - 1];

for (int i = len - 1; i > 0; i--) {
    a1[i] ^= a1[i - 1];
    a1[i] ^= a2[i];
}

a1[0] ^= a2[0];
```

fileciteturn3file10L244-L247

### Agent 规则

遇到：

```text
多层 Base64
+
反调试
+
运行时生成表
```

不要只静态解码：

```text
先绕过反调试
 ↓
动态获取最终表
 ↓
恢复逆变换
 ↓
批量解码
```

---

## 3.5 Babyre

### 核心

存在反调试，需要绕过后动态分析。

题目实现了自定义的类似 TEA/XTEA 的 32-bit 分组运算：

```text
num_rounds
v[2]
key[4]
delta = 0x88408067
```

同时存在自定义 `decipher` / `encipher`。

### Agent 规则

遇到：

```text
TEA/XTEA-like
uint32_t
v0/v1
key[4]
delta
sum
```

应识别为：

```text
TEA 家族/自定义 TEA-like
```

并优先：

```text
提取 key
确认轮数
确认 delta
确认 sum 初值
确认加密/解密方向
动态验证
```

---

## 3.6 SpeedUp

### 题目特征

需要计算一个超大数十进制展开后的每一位数字之和。

### Agent 规则

遇到：

```text
超大整数
不能直接展开
要求十进制各位数字和
```

不要使用普通整数直接计算。

优先：

```text
寻找数学性质
快速幂/大整数算法
高效十进制转换
已有高性能实现
```

原 Writeup 直接使用可处理该问题的 C++ 实现。fileciteturn3file17L387-L390

---

## 3.7 找到PNG了吗

### 取证链

原题附件为 VEM。

分析流程：

```text
VEM
 ↓
制作 profile
 ↓
Volatility 2
 ↓
识别 Ubuntu 20.04
 ↓
dump-dir 导出
 ↓
分析导出文件
 ↓
发现 6000.vma
 ↓
发现 socket 交互痕迹
 ↓
搜索 "please give"
 ↓
找到相关脚本
 ↓
发现 RC4
 ↓
恢复 key
 ↓
利用 PNG 文件头
 ↓
解密图片
```

关键 RC4 密钥：

```text
do_not_care
where_is_the_key
```

原文指出利用 PNG 文件头进行已知明文处理，再使用 CyberChef 解密，最终得到：

```text
flag{It’s_So_Hard_ToFind_A_Picture}
```

fileciteturn2file15L420-L437

### Agent 规则

遇到内存镜像：

```text
先识别操作系统
 ↓
制作/选择正确 profile
 ↓
Volatility
 ↓
dump
 ↓
搜索关键词
 ↓
寻找进程/脚本/socket
 ↓
恢复加密算法和密钥
```

如果是图片加密：

```text
检查 PNG magic
89 50 4E 47
```

并考虑已知明文攻击。

标签：

```text
forensics
VEM
Volatility2
Ubuntu
memory-dump
RC4
known-plaintext
PNG
```

---

# 4. PWN

## 4.1 WTOA

### 静态定位

原 Writeup 通过调试确定：

```text
main logic: 0x2150
menu:       0x2120
getinput:   0x3EF0
output:     0x3DD0
atoi:       0x2990
add:        0x12F0
delete:     0x19C0
edit:       0x15D0
show:       0x1BA0
exit:       0x2900
```

flag 虚拟地址：

```text
0x501b40
```

注意：原 Writeup 特别说明这些是虚拟地址，需要结合程序基地址进行访问。fileciteturn3file1L38-L52

### Agent 规则

遇到题目只有 stripped ELF：

```text
菜单题
+
add/delete/edit/show
```

优先建立：

```text
函数地址表
功能 → 函数
全局变量
flag 地址
基址
```

然后检查：

```text
UAF
double free
格式化字符串
越界
任意读
任意写
```

---

## 4.2 simpleinterpreter

### 核心漏洞

这是 C 解释器。

原 Writeup 指出核心问题来自 C 指针操作：

```c
memory_addr = &memory_addr;
```

获得自身地址后，通过偏移计算：

```text
栈地址
libc 地址
```

然后：

```text
泄露地址
 ↓
定位返回地址
 ↓
栈上 ROP
 ↓
控制流劫持
```

漏洞位于功能 11：

```text
*v21 = qword_205090;
```

相关 debug symbol 位于：

```text
.bss:0x2050F8
.bss:0x205100
```

### Agent 规则

如果解释器允许：

```text
指针运算
任意地址偏移
memory 地址操作
```

检查：

```text
是否可以从已知地址推导栈
是否可以推导 libc
是否可以修改返回地址
是否存在 ROP
```

标签：

```text
C-interpreter
pointer-arithmetic
stack-leak
libc-leak
ROP
ret-hijack
```

---

## 4.3 chatting

### 漏洞

向不存在用户发送消息：

```text
申请堆块
 ↓
检查用户不存在
 ↓
释放堆块
```

重复调用后导致：

```text
double free
```

原 Writeup 的利用：

```text
填满 tcache
 ↓
在 fastbin 上触发 double free
 ↓
控制堆分配
 ↓
覆盖 __free_hook
 ↓
写入 system
 ↓
触发 free("/bin/sh")
```

### Agent 规则

发现：

```text
malloc
+
失败路径 free
+
重复请求
```

必须检查：

```text
异常路径是否重复释放
对象状态是否清零
指针是否仍然可用
```

标签：

```text
heap
double-free
fastbin
tcache
__free_hook
system
```

---

## 4.4 warmup23

### 核心漏洞

glibc 2.35 下的：

```text
off-by-null
```

原 Writeup 参考 off-by-null 利用，并通过调整 barrier chunk 大小布置堆布局。

核心利用链：

```text
off-by-null
 ↓
构造 fake chunk fd/bk
 ↓
堆重叠
 ↓
两个 index 指向同一 chunk
 ↓
tcache 填满
 ↓
double free
 ↓
修改 tcache 结构
 ↓
任意地址写
 ↓
stdout 泄露栈地址
 ↓
栈上 ORW
```

### Agent 规则

发现：

```text
1 字节 NULL 溢出
glibc 2.35
large chunk
```

检查：

```text
prev_size
size
PREV_INUSE
fake chunk
chunk overlap
tcache
stdout
```

标签：

```text
off-by-null
glibc-2.35
heap-overlap
tcache-poisoning
arbitrary-write
stdout-leak
ORW
```

---

## 4.5 A-rtsp

### 协议识别

题目是 RTSP 服务。

关键请求：

```text
SETUP
GET_PARAMETER
SET_PARAMETER
DESCRIBE
```

`SETUP` 可用于获得 Session。

随后通过 RTSP 请求触发漏洞函数。原题请求格式中存在：

```text
GET_PARAMETER
CSeq
Session
User-Agent
Accept
Content-Type
GET_INFO
```

### 漏洞利用

原 Writeup 使用：

```text
RTSP 参数注入
 ↓
vul_string
 ↓
控制栈数据
 ↓
ROP
 ↓
read/send
```

最终通过：

```text
DESCRIBE rtsp://127.0.0.1:8554/wavAudioTest RTSP/1.0
vul_string: <ROP>
```

将 ROP 链放入协议字段。fileciteturn3file4L117-L128

### Agent 规则

遇到：

```text
RTSP
自定义请求头
字符串字段
```

重点检查：

```text
strcpy
sprintf
memcpy
scanf
固定长度 buffer
协议字段长度
```

并建立：

```text
协议请求
 ↓
漏洞字段
 ↓
栈溢出
 ↓
libc/proc base
 ↓
ROP
```

---

# 5. Crypto

## 5.1 not only rsa

### 漏洞

RSA 参数：

```text
n = p^5
```

原 Writeup 直接通过因式分解发现：

```text
n = p^5
```

然后得到：

```text
p
e
c
```

在 SageMath 中计算：

```python
rs = mod(c, p^5).nth_root(e, all=True)
```

再把结果转换成字节并搜索：

```text
b"flag"
```

得到 flag。fileciteturn1file2L72-L77

### Agent 规则

RSA 遇到：

```text
n
e
c
```

不要默认直接做标准 RSA。

优先检查：

```text
factor(n)
gcd(e, phi)
p == q
n 是否是 p^k
低指数
广播
共模
小私钥
```

特别是：

```text
n = p^k
```

属于严重结构泄露。

标签：

```text
RSA
weak-modulus
perfect-power
p^k
nth-root
SageMath
```

---

# 6. Web

## 6.1 happgame

### 核心漏洞

题目使用：

```text
gRPC
Java
反序列化
```

原 Writeup 使用：

```text
CommonsCollections6
```

生成序列化数据，再通过 gRPC：

```text
helloworld.Greeter.ProcessMsg
```

的：

```json
{"serializeData": "..."}
```

传入 Base64 数据。

### 利用链

```text
gRPC
 ↓
serializeData
 ↓
Base64
 ↓
Java 反序列化
 ↓
CommonsCollections6
 ↓
命令执行
```

原文明确给出了 `grpcurl` 调用方式及 CC6 序列化链。fileciteturn3file6L166-L172

### Agent 规则

发现：

```text
gRPC
+
serializeData
+
Java
```

优先检查：

```text
ObjectInputStream
readObject
反序列化
ysoserial
CommonsCollections
```

---

## 6.2 thinkshop

### 环境

原 Writeup 指出容器内 PHP：

```text
PHP 5.6.40
Ubuntu 18.04
```

### Step 1：登录绕过

关键代码：

```php
$adminData = Db::table('admin')
    ->cache(true, $Expire)
    ->find($username);
```

后续利用 ThinkPHP 对象/缓存/反序列化链。

原文中出现：

```text
think\session\driver\Memcache
think\cache\driver\Memcached
```

并构造序列化对象链。fileciteturn2file12L328-L350

最终：

```text
反序列化
 ↓
ThinkPHP 对象链
 ↓
文件/过滤器
 ↓
RCE
 ↓
读取根目录 flag
```

原文明确指出最终通过 RCE 读取根目录 flag。fileciteturn3file7L189-L193

### Agent 规则

发现：

```text
ThinkPHP
+
PHP 5.x
+
cache/session
+
unserialize
```

检查：

```text
POP chain
session driver
cache driver
Memcache/Memcached
php://filter
文件操作
Process
```

标签：

```text
PHP
ThinkPHP
deserialization
POP-chain
session
cache
php-filter
RCE
```

---

# 7. RE

## 7.1 ezre

### 反调试

程序：

```text
init array
 ↓
fork
 ↓
父进程 ptrace 子进程
 ↓
监控 main
 ↓
真正检查逻辑
```

直接静态分析会受到干扰。

原 Writeup 的绕过：

```text
先运行程序
 ↓
read 阻塞
 ↓
gdb attach
 ↓
下断点
 ↓
进入真正检查函数
```

fileciteturn3file3L96-L105

### Agent 规则

检测：

```text
fork
ptrace
PTRACE_ATTACH
init_array
```

不要立即尝试完全静态恢复。

优先：

```text
运行
 ↓
让程序进入阻塞点
 ↓
attach
 ↓
断点
 ↓
动态获取输入处理逻辑
```

标签：

```text
anti-debug
ptrace
fork
gdb-attach
dynamic-analysis
```

---

## 7.2 dotdot

### 核心流程

C# 程序：

```text
输入
 ↓
BBB
 ↓
AAA
 ↓
CCC 检查
 ↓
读取 License.dat
 ↓
EEE
 ↓
BinaryFormatter.Deserialize
 ↓
输出
```

原 Writeup 发现 `AAA` 中存在复杂表运算。

之后：

```text
得到 WelcomeToQWB2023
 ↓
RC4 解 License.dat
 ↓
BinaryFormatter 反序列化
 ↓
出现异常
 ↓
修复序列化数据
 ↓
动态调试
 ↓
定位解密结果
```

原文指出 `License.dat` 后续通过 `FFF` 进行检查，`b` 长度必须为 21，并且输入会进行自定义运算。fileciteturn2file10L259-L285

### 反序列化修复

原 Writeup 分析出对象固定格式。

字符串对象：

```text
06
06
4 字节长度
实际字符串
```

通过补齐丢失字段，使反序列化继续进行。

fileciteturn2file2L64-L70

### Agent 规则

遇到：

```text
C#
BinaryFormatter
License.dat
自定义表
RC4
```

优先：

```text
反编译
定位输入
定位加密函数
恢复 key
动态调试
检查序列化格式
修复截断/损坏数据
```

标签：

```text
C#
BinaryFormatter
serialization
RC4
custom-table
dynamic-analysis
```

---

# 8. Agent 可复用攻击模式

## Pattern-001：Python Jail 过滤器污染

```text
检测：
locals / globals / filter / len / input

动作：
修改上下文对象
 ↓
覆盖过滤器
 ↓
覆盖检查函数
 ↓
恢复输入
 ↓
访问 builtins
```

---

## Pattern-002：模板 → Spring Bean → XML → ProcessBuilder

```text
模板执行
 ↓
Spring Bean
 ↓
ClassLoader
 ↓
动态拼接被过滤类名
 ↓
ClassPathXmlApplicationContext
 ↓
加载 XML
 ↓
ProcessBuilder
 ↓
命令执行
```

---

## Pattern-003：格式化字符串 → libc leak → 半字写

```text
format string
 ↓
%p 泄露
 ↓
计算 libc base
 ↓
%hn/%hhn 修改目标
 ↓
one_gadget / ROP
```

---

## Pattern-004：失败路径 Double Free

```text
malloc
 ↓
业务检查失败
 ↓
free
 ↓
对象状态未正确清理
 ↓
重复请求
 ↓
double free
 ↓
tcache/fastbin
 ↓
任意写
```

---

## Pattern-005：Off-by-null → 堆重叠

```text
off-by-null
 ↓
破坏 size/PREV_INUSE
 ↓
fake chunk
 ↓
overlap
 ↓
两个逻辑对象指向同一物理 chunk
 ↓
double free / tcache poisoning
 ↓
任意地址写
```

---

## Pattern-006：协议字段栈溢出

```text
识别协议
 ↓
定位可控字符串字段
 ↓
长度验证
 ↓
栈 buffer
 ↓
覆盖返回地址
 ↓
ROP
```

适用于本题 RTSP 场景。

---

## Pattern-007：弱 RSA 模数

```text
RSA
 ↓
检查 n
 ↓
检查 perfect power
 ↓
n == p^k
 ↓
恢复 p
 ↓
恢复明文
```

---

## Pattern-008：Java 反序列化

```text
gRPC/HTTP
 ↓
serializeData
 ↓
Base64
 ↓
Java deserialize
 ↓
CommonsCollections
 ↓
命令执行
```

---

## Pattern-009：PHP ThinkPHP POP Chain

```text
ThinkPHP
 ↓
session/cache
 ↓
unserialize
 ↓
POP chain
 ↓
文件/过滤器
 ↓
RCE
```

---

## Pattern-010：反调试程序动态接管

```text
init_array
 ↓
fork
 ↓
ptrace
 ↓
数据被破坏/检查逻辑隐藏
 ↓
运行并阻塞
 ↓
gdb attach
 ↓
真实逻辑动态分析
```

---

## Pattern-011：内存取证 + 加密文件

```text
VEM/内存镜像
 ↓
识别 OS
 ↓
Volatility
 ↓
dump
 ↓
关键词搜索
 ↓
定位脚本/socket
 ↓
恢复加密算法/key
 ↓
利用文件格式已知明文
 ↓
解密
```

---

# 9. Agent 检索标签

```yaml
misc:
  - fuzzing
  - black-box
  - oracle
  - pyjail
  - procfs
  - environment-variable
  - spring
  - LFI
  - ClassLoader
  - ProcessBuilder
  - ADS-B
  - Mode-S
  - ICAO
  - forensics
  - VEM
  - Volatility2
  - RC4
  - known-plaintext

pwn:
  - format-string
  - fmtstr
  - one-gadget
  - trie
  - arbitrary-read
  - pointer-arithmetic
  - stack-leak
  - libc-leak
  - double-free
  - fastbin
  - tcache
  - off-by-null
  - heap-overlap
  - tcache-poisoning
  - stdout-leak
  - ORW
  - RTSP
  - stack-overflow
  - ROP

crypto:
  - RSA
  - p^5
  - perfect-power
  - nth-root

web:
  - gRPC
  - Java-deserialization
  - CommonsCollections
  - ThinkPHP
  - PHP5
  - POP-chain
  - php-filter
  - RCE

reverse:
  - anti-debug
  - ptrace
  - fork
  - gdb-attach
  - Base64
  - custom-cipher
  - TEA-like
  - RC4
  - BinaryFormatter
  - C#
```

---

# 10. Agent 输出格式建议

当 Agent 从本知识库命中案例后，不应直接回答“这是某题的 Payload”。

推荐输出：

```yaml
matched_case:
  event: 强网杯2023
  challenge: <命中的题目>
  category: <分类>

evidence:
  - <目标中的特征>
  - <对应 Writeup 中的特征>

vulnerability:
  type: <漏洞/算法>
  primitive: <当前可获得原语>

attack_chain:
  - <阶段1>
  - <阶段2>
  - <阶段3>

next_actions:
  - <下一步验证>
  - <下一步利用>

confidence:
  level: high|medium|low
  reason: <原因>
```

---

# 11. 重要原则

### 原则 A：优先抽象漏洞，不记忆固定目标

错误：

```text
47.x.x.x:1337 → 某 Payload
```

正确：

```text
format string
 → libc leak
 → %hn
 → one_gadget
```

### 原则 B：把 Writeup 当“案例”，不是唯一答案

例如：

```text
double free
```

并不意味着必须使用：

```text
__free_hook
```

Agent 应根据：

```text
glibc 版本
保护机制
可控地址
已有 leak
```

重新决定最终原语。

### 原则 C：先建立原语，再设计最终利用

```text
输入控制
 ↓
任意读/任意写/信息泄露
 ↓
地址计算
 ↓
控制流
 ↓
最终目标
```

### 原则 D：遇到反调试优先动态验证

```text
静态分析异常
 ↓
检查 fork/ptrace/init_array
 ↓
尝试运行 + attach
 ↓
观察真实数据
```

### 原则 E：所有历史远程地址均视为失效题目环境

Agent 不应把 Writeup 中的：

```text
IP
端口
临时 Token
反弹地址
```

作为当前目标。

---

# 12. 来源与可信度

**主要来源：**

- 星盟安全团队：《强网杯2023-Writeup》
- 页面日期：2023-12-18
- 本知识库中的具体题解、题目名称、漏洞描述、代码和结果均来自用户上传的原始 HTML。

例如原文明确列出题目目录及分类。fileciteturn3file0L15-L15

对于原 Writeup 没有展开说明的题目，本知识库不自行补充不存在于原文中的漏洞细节。

---

# 13. 推荐 RAG Chunk 切分

建议向量数据库按下面粒度切分：

```text
chunk 1  → 赛事元数据
chunk 2  → easyfuzz
chunk 3  → Pyjail myFILTER
chunk 4  → Hello Spring
chunk 5  → Happy Chess
chunk 6  → Pyjail MyRevenge
chunk 7  → 谍影重重
chunk 8  → ez_fmt
chunk 9  → 石头剪刀布
chunk 10 → tire
chunk 11 → ezre
chunk 12 → Babyre
chunk 13 → SpeedUp
chunk 14 → 找到PNG了吗
chunk 15 → WTOA
chunk 16 → simpleinterpreter
chunk 17 → chatting
chunk 18 → warmup23
chunk 19 → A-rtsp
chunk 20 → not only rsa
chunk 21 → happgame
chunk 22 → thinkshop
chunk 23 → RE ezre
chunk 24 → dotdot
chunk 25+ → 攻击模式抽象
```

每个 chunk 建议 metadata：

```json
{
  "event": "强网杯2023",
  "source": "星盟安全团队",
  "category": "PWN",
  "challenge": "warmup23",
  "tags": [
    "off-by-null",
    "heap-overlap",
    "tcache",
    "arbitrary-write",
    "ORW"
  ],
  "knowledge_type": "case"
}
```

这样 AgentScope 的检索可以先：

```text
漏洞类型检索
      ↓
历史案例召回
      ↓
攻击原语匹配
      ↓
环境条件过滤
      ↓
生成下一步行动
```

而不是简单地把整篇 Writeup 当成一个超长文档。
