# CTF Misc 方向通用技巧

> 关键词:CTF,Misc,杂项,隐写,LSB,PNG,eml邮件,PowerShell混淆,免杀,二维码,动态二维码,取证,编码,Base64,Deflate,SecureString
> 本文件提炼自 NCTF2023 Writeup 及通用 Misc CTF 经验,覆盖隐写、文件分析、混淆代码解包三大类。

## 一、图片隐写(LSB)

### 原理

PNG/BMP 图像每个颜色通道的低位(Least Significant Bit)对人眼不可见,常被用于隐藏数据。常见变体:
- 最低 1 位(bit-plane)提取;
- 低 2~4 位提取(本题:第 2、3 通道各取低 4 位拼 1 字节);
- RGB 各取 1 位合成、按行/列序、隔行等。

### 提取思路

1. 先用 `zsteg`/`stegsolve` 快速扫描常见 LSB 组合;
2. 题目给提示(如"Invoke-image 免杀")时,按脚本逻辑还原字节;
3. 提取结果可能是文件(写入磁盘后用 `file` 识别)或字符串。

### 示例(NCTF2077 jackpot:两通道低 4 位拼字节)

```python
from PIL import Image

def solve_png(image_path):
    img = Image.open(image_path)
    width, height = img.size
    extract_data = bytearray()
    for y in range(height):
        for x in range(width):
            r, g, b, *_ = img.getpixel((x, y))
            extract_byte = (g & 0x0F) | ((b & 0x0F) << 4)
            extract_data.append(extract_byte)
    return extract_data

data = solve_png("nctf.png")
with open('1.bin', 'wb') as f:
    f.write(data)
```

### 常用工具

| 工具 | 用途 |
| --- | --- |
| zsteg | PNG/BMP 自动 LSB 扫描 |
| Stegsolve | 图像通道/位平面可视化分析 |
| binwalk / foremost | 文件分离与隐藏文件提取 |
| strings / file | 常规排查 |

## 二、邮件(eml)与文件包分析

- **eml 文件**本质是 MIME 文本:用文本编辑器或 `eml_parser`(Python)解析,提取正文、附件(可含 png/exe/加密压缩包)、邮件头(发件人/服务器/时间线)。
- 附件可能是**嵌套载体**(如把 exe 嵌入图片),先 `file` 识别再分离。
- 可执行附件可提交**在线沙箱**(如微步云沙箱)动态分析,获取行为与 flag。
- 配套:zip 伪加密、压缩包密码(明文攻击/字典/CRC 爆破)也是 Misc 高频点。

## 三、PowerShell 混淆载荷逐层解包

CTF 与真实钓鱼样本中,PowerShell 载荷常多层混淆,特征与解包链:

### 常见混淆层

1. **Base64**:`[Convert]::FromBase64String('...')`
2. **压缩**:`DeflateStream` / `GZipStream` + `MemoryStream` 解压
3. **字符串翻转/拼接/字符替换**:如 `'20_2er28:...'.sPlIT('<r_l:{&Z')` 按分隔符拆、转 16 进制、转字符再拼接
4. **对象/变量名大小写混淆、反引号、`-join ''`**:提高人工阅读难度
5. **SecureString**:`ConvertTo-SecureString -String <密文> -Key <字节数组>`,还原口令需再用 `PSCredential.GetNetworkCredential().Password`

### 解包方法论

1. **由内到外逐层解码**,每层结果单独保存(命名 `layer1.txt`...);
2. 关注关键字: `FromBase64String`、`DeflateStream`、`Decompress`、`ReadToEnd`、`ConvertTo-SecureString`、`GetNetworkCredential`、`IEX`/`Invoke-Expression`;
3. 混淆字符串常见处理:按分隔符 split → `[convert]::toint16(s, 16)` → `[char]` → `-join ''`;
4. 识别**免杀框架特征**:`Invoke-image`(图片隐写免杀)、`Invoke-Obfuscation`、`Cobalt Strike` 的 PowerShell stager;
5. 解密 SecureString:提取 `-Key` 字节数组,用 PSCredential 还原。

### 还原 SecureString 示例

```powershell
$EncryptedPW = Get-Content -Path key.txt
$SecureString = ConvertTo-SecureString -String $EncryptedPW -Key (143..112)
$Credentials = New-Object System.Management.Automation.PSCredential "User", $SecureString
$Credentials.GetNetworkCredential().Password
```

### 防御视角(蓝队)

- 终端启用 ScriptBlock 日志、AMSI、WDAC/AppLocker 限制 PowerShell;
- 关注 `powershell -enc`、`IEX`、从 `FromBase64String`+解压模式的进程命令行;
- 相关:05-应急响应/WebShell与后门排查.md、03-安全运维/日志管理与分析.md。

## 四、二维码类题目

| 场景 | 思路 |
| --- | --- |
| 动态/闪烁二维码 | 完整图案出现瞬间截图;视频可逐帧 `ffmpeg` 抽帧 + `zbarimg` 批量识别 |
| 残缺二维码 | 用二维码容错(约 30%)直接扫;补定位角/掩码 |
| 坐标点阵还原二维码 | 数据为 (x, y, value) 时用 matplotlib 画散点图还原图案(见下) |
| 反色/旋转/镜像 | Stegsolve/图像处理翻转后重扫 |

### 坐标还原示例(Unity 游戏 Jump For Flag)

```python
import matplotlib.pyplot as plt
x, z, colors = [], [], []
with open('hint.txt') as f:
    for line in f:
        arr = line.split()
        if len(arr) >= 3:
            x.append(int(arr[0]))
            z.append(int(arr[1]))
            colors.append('black' if int(arr[2]) == 1 else 'white')
plt.scatter(x, z, c=colors, marker='s', s=100)
plt.show()
```

Unity/游戏类题目:用 dnspy(Windows)/Il2CppDumper(Il2Cpp)分析 `Assembly-CSharp.dll`,找到绘制二维码的坐标数据与颜色判定字段。

## 五、Misc 通用排查流程

1. `file` 识别文件真实类型(注意改后缀);
2. `strings` 快速找 flag 特征(`flag{`/`NCTF{`/base64);
3. `binwalk`/`foremost` 分离隐藏文件;
4. 隐写工具扫描(zsteg/stegsolve/outguess 等);
5. 编码识别与多重解码(常见:base64/hex/url/rot13/培根/摩斯);
6. 取证类:看文件元数据、时间线、恢复删除文件。

## 合规声明

以上分析手法适用于 CTF 题目与授权取证的样本;对真实恶意样本分析应在隔离环境进行。
