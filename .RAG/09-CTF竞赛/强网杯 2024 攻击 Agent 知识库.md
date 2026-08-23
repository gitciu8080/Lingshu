# 强网杯 2024 攻击 Agent 知识库
> 关键词:强网杯2024,Writeup,攻击Agent,攻击路径推理,CTF,PWN,Web,Reverse,Misc,Crypto

> 数据来源：XMCVE-Polaris《强网杯 2024 Writeup》
>
> 用途：CTF / 靶场 / 授权安全测试环境中的攻击路径推理、漏洞识别与利用策略检索。
>
> 注意：本知识库用于授权环境。Agent 在真实目标上执行攻击前，应确认目标属于明确授权范围。

---

## 一、知识库元数据

| 项目 | 内容 |
|---|---|
| 赛事 | 第八届强网杯全国网络安全挑战赛 |
| 时间 | 2024 |
| 团队 | XMCVE-Polaris |
| 知识类型 | CTF Writeup / 漏洞利用 / 攻击链 |
| 主要方向 | PWN / Web / Reverse / Misc / Crypto |
| 适用 Agent | 攻击 Agent、漏洞分析 Agent、逆向 Agent、PWN Agent |
| 数据来源 | XMCVE 官方博客 |

---

# 二、Agent 总体使用规则

攻击 Agent 不应该把 Writeup 当成“固定 Payload 数据库”，而应该把它理解成：

```text
题目特征
    ↓
漏洞模式识别
    ↓
利用条件判断
    ↓
原语建立
    ↓
信息泄露
    ↓
地址计算
    ↓
权限/控制流劫持
    ↓
目标文件或 flag 获取
```

Agent 应优先提取：

- 漏洞类型
- 漏洞触发条件
- 输入位置
- 长度限制
- 内存布局
- 可获得的原语
- 地址泄露方式
- 缓解机制
- 沙盒限制
- 最终利用目标

---

# 三、PWN 知识

## PWN-001：整数溢出导致资源/货币异常

### 漏洞模式

当程序存在：

```c
total = price * count;
```

或者：

```c
money -= price * count;
```

而 `price` / `count` 没有进行范围检查时，应重点检查整数溢出。

### Agent 检测规则

发现以下代码模式时提高漏洞优先级：

```c
int price;
int count;

total = price * count;
```

尤其关注：

```text
signed integer overflow
unsigned integer wraparound
negative number
size_t/int 类型转换
乘法后再进行余额判断
```

### 利用思路

```text
控制数量
    ↓
构造超大乘积
    ↓
整数回绕
    ↓
实际扣款异常
    ↓
获得异常数量资源
    ↓
使用资源触发后续漏洞
```

### Agent 行动

```text
1. 枚举可控数量参数
2. 获取 price
3. 判断整数类型和位宽
4. 测试边界值
5. 测试 2^n 附近值
6. 检查乘法结果是否参与余额判断
7. 判断是否能够获得异常资源
8. 判断该资源是否能够触发其他攻击面
```

---

# 四、PWN-002：无长度限制的字符串复制导致堆溢出

## 漏洞特征

重点搜索：

```c
strcpy()
memcpy()
copy()
sprintf()
gets()
scanf("%s")
```

以及自定义字符串复制函数。

如果目标缓冲区大小固定，但复制长度由攻击者控制：

```text
攻击者输入
    ↓
无长度检查
    ↓
覆盖相邻堆对象
    ↓
修改对象成员
    ↓
修改函数指针 / 数据指针
```

---

## PWN-003：堆溢出修改对象指针

### 典型攻击模式

如果堆对象类似：

```text
object
├── field 0
├── field 1
├── pointer
└── description
```

而溢出可以覆盖：

```text
object + offset
```

中的指针，则应立即检查该指针是否：

- 被 `cout` / `printf` 输出
- 被 `memcpy` 写入
- 被 `read` 写入
- 被函数调用
- 被解引用
- 被作为数组地址使用

### 可形成的原语

```text
堆溢出
    ↓
修改目标指针
    ↓
读取目标地址
    ↓
任意地址读
```

或者：

```text
堆溢出
    ↓
修改目标指针
    ↓
向目标地址写入数据
    ↓
任意地址写
```

---

# 五、任意地址读写原语

当 Agent 获得：

```text
Arbitrary Read
Arbitrary Write
```

后，不应立即执行控制流劫持。

优先建立：

```text
heap leak
    ↓
libc leak
    ↓
stack leak
    ↓
返回地址定位
    ↓
ROP / 控制流劫持
```

---

# 六、堆地址泄露

现代 glibc 堆可能存在指针加密。

因此：

```text
泄露堆指针
    ↓
判断是否为编码指针
    ↓
识别 safe-linking
    ↓
恢复 key / heap base
```

Agent 应重点识别：

```text
fd
next
tcache
safe-linking
PROTECT_PTR
```

---

# 七、Safe-Linking 地址恢复

如果泄露数据表现为：

```text
encoded_ptr
```

不要直接将其当成堆地址。

典型关系：

```text
encoded = ptr ^ (heap_address >> 12)
```

因此需要：

```text
泄露编码值
+
已知堆地址/相邻指针
        ↓
恢复编码密钥
        ↓
计算真实 heap address
```

### Agent 推理模板

```text
如果：
    泄露值看起来不像 canonical pointer

并且：
    目标位于 tcache / fastbin 等堆管理结构

则：
    检查 glibc safe-linking

如果存在：
    尝试根据已知指针恢复编码关系
```

---

# 八、信息泄露后的攻击链

标准攻击链：

```text
漏洞
 ↓
堆溢出
 ↓
任意地址读写
 ↓
泄露 heap
 ↓
泄露 libc
 ↓
泄露 stack
 ↓
定位返回地址
 ↓
栈迁移
 ↓
ROP
 ↓
读取 flag
```

---

# 九、沙盒环境下的利用策略

如果检测到：

```text
seccomp
sandbox
syscall filter
```

Agent 不应默认使用：

```text
system("/bin/sh")
execve("/bin/sh")
```

而应该首先分析：

```text
允许的 syscall
```

然后建立 syscall-oriented exploitation。

例如：

```text
open/openat
    ↓
read
    ↓
write
```

目标从：

```text
获得 shell
```

转化为：

```text
直接读取目标文件
```

---

# 十、ROP 构造策略

当存在：

```text
任意地址写
+
栈地址泄露
+
可控返回地址
```

可以考虑：

```text
stack pivot
```

典型思路：

```text
修改返回地址
        ↓
pop rsp ; ret
        ↓
RSP → attacker-controlled heap
        ↓
执行堆上的 ROP chain
```

### Agent 检查

搜索 gadget：

```text
pop rsp
leave ; ret
xchg rsp, ...
```

然后判断：

```text
是否可以控制 RSP
```

---

# 十一、栈地址定位

如果：

```text
environ
```

可读取，可以利用：

```text
libc.environ
```

获得栈地址附近的位置。

然后：

```text
environ
 ↓
遍历栈
 ↓
寻找已知堆地址 / ROP 数据 / 返回地址特征
 ↓
确定目标返回地址
```

---

# 十二、ROP 最终目标

在沙盒环境中优先：

```text
open flag
read flag
write flag
```

而不是：

```text
system("/bin/sh")
```

逻辑：

```text
fd = open("/flag", ...)
read(fd, buf, ...)
write(1, buf, ...)
```

---

# 十三、Web 漏洞知识

Agent 分析 Web 题时按照：

```text
入口
 ↓
参数
 ↓
身份认证
 ↓
权限检查
 ↓
文件操作
 ↓
数据库
 ↓
模板
 ↓
反序列化
 ↓
命令执行
```

进行审计。

重点关注：

```text
SQL Injection
SSTI
SSRF
文件读取
文件上传
路径穿越
反序列化
命令注入
权限绕过
JWT
Session
原型污染
```

---

# 十四、Web Agent 决策规则

发现用户可控参数时：

```text
参数
 ↓
是否进入数据库？
 ↓
是否进入模板？
 ↓
是否进入文件路径？
 ↓
是否进入系统命令？
 ↓
是否进入网络请求？
 ↓
是否进入反序列化？
```

对应：

| 数据流 | 优先检查 |
|---|---|
| 参数 → SQL | SQL 注入 |
| 参数 → 模板 | SSTI |
| 参数 → 文件路径 | 路径穿越 / 任意文件读取 |
| 参数 → 命令 | 命令注入 |
| 参数 → URL | SSRF |
| 参数 → pickle / unserialize | 反序列化 |
| 参数 → HTML | XSS |
| 参数 → 权限对象 | 权限绕过 |

---

# 十五、Reverse Agent 知识

逆向题统一采用：

```text
文件识别
 ↓
架构识别
 ↓
保护机制
 ↓
入口函数
 ↓
字符串
 ↓
交叉引用
 ↓
关键函数
 ↓
输入处理
 ↓
校验算法
 ↓
关键常量
 ↓
逆向算法
```

---

# 十六、IDA 自动分析规则

Agent 使用 IDA 时优先执行：

```text
strings
imports
exports
xrefs
functions
call graph
```

重点寻找：

```text
strcmp
strncmp
memcmp
scanf
read
recv
gets
strcpy
memcpy
system
execve
open
read
write
```

如果是 C++：

```text
std::string
std::vector
std::map
std::cout
operator new
operator delete
```

需要特别关注对象生命周期和虚函数表。

---

# 十七、Fuzzing Agent 规则

当：

```text
源码缺失
C++ 复杂
输入接口多
字符串命令解析
```

优先考虑 fuzzing。

流程：

```text
识别输入接口
 ↓
建立最小输入
 ↓
枚举命令
 ↓
变异长度
 ↓
变异整数
 ↓
特殊字符
 ↓
边界值
 ↓
崩溃分类
 ↓
GDB/IDA 定位
```

重点测试：

```text
0
-1
INT_MAX
INT_MIN
0x7fffffff
超长字符串
空字符串
重复命令
异常状态切换
```

---

# 十八、攻击 Agent 知识检索标签

```yaml
tags:
  - qiangwangbei
  - ctf
  - pwn
  - heap
  - heap-overflow
  - integer-overflow
  - arbitrary-read
  - arbitrary-write
  - safe-linking
  - libc-leak
  - heap-leak
  - stack-leak
  - environ
  - stack-pivot
  - ROP
  - seccomp
  - syscall
  - flag-read
  - web
  - reverse
  - fuzzing
  - IDA
```

---

# 十九、Agent 推理 Prompt 模板

当攻击 Agent 遇到新题目时，可以使用：

```text
你正在分析一个授权 CTF/靶场目标。

请将目标与强网杯 2024 知识库进行模式匹配。

优先检查：

1. 是否存在整数溢出
2. 是否存在无长度限制的字符串复制
3. 是否存在堆溢出
4. 是否可以覆盖堆对象中的指针
5. 是否可以建立任意地址读
6. 是否可以建立任意地址写
7. 是否存在 safe-linking
8. 是否能够泄露 heap
9. 是否能够泄露 libc
10. 是否能够通过 environ 定位 stack
11. 是否能够进行 stack pivot
12. 是否存在 seccomp
13. 如果存在 seccomp，分析允许的 syscall
14. 优先设计直接读取目标文件的 ROP，而不是依赖 shell

输出：

- 漏洞类型
- 证据
- 利用前提
- 当前已有原语
- 下一步应该验证的条件
- 推荐利用链
- 如果失败，下一条备用路径
```

---

# 二十、攻击链抽象

本知识库中最重要的攻击链抽象为：

```text
资源异常
    ↓
触发隐藏功能
    ↓
堆溢出
    ↓
对象指针覆盖
    ↓
任意地址读写
    ↓
泄露堆地址
    ↓
恢复堆指针编码
    ↓
扩大任意地址读写能力
    ↓
泄露 libc / stack
    ↓
定位返回地址
    ↓
栈迁移
    ↓
ROP
    ↓
绕过沙盒限制
    ↓
open/read/write
    ↓
读取目标文件
```

---

# 二十一、知识库使用原则

攻击 Agent 不应该只记忆：

```text
某题 Payload = xxx
```

而应该学习：

```text
某种漏洞
    →
可以产生什么原语
    →
什么信息可以泄露
    →
泄露后如何计算地址
    →
如何扩大权限
    →
如何完成最终控制
```

即：

```text
漏洞知识
+
利用原语
+
环境约束
+
缓解机制
+
攻击链
=
可迁移攻击知识
```

---

# 二十二、来源

原始资料：

XMCVE 星盟安全团队官方博客：

https://blog.xmcve.com/

赛事信息及团队公开资料显示，XMCVE-Polaris 在第八届强网杯 2024 线上赛排名第 21，并在同年决赛排名第 12。

---

# 二十三、知识库后续扩展格式

后续加入其他 Writeup 时，统一采用：

```text
[赛事]
    ↓
[题目]
    ↓
[漏洞类型]
    ↓
[漏洞触发条件]
    ↓
[漏洞原语]
    ↓
[信息泄露]
    ↓
[地址计算]
    ↓
[缓解机制]
    ↓
[绕过方式]
    ↓
[最终利用]
    ↓
[Agent 决策规则]
```

这样可以让 Agent 从“记住一道 CTF 题”升级为：

```text
识别漏洞模式
        ↓
复用历史攻击原语
        ↓
自动构建攻击链
        ↓
根据目标环境动态调整利用方式
```
