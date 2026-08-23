# TonyEnc / TonyDec 识别与解密知识
> 关键词:TonyEnc,TonyDec,加密识别,解密,CTF,算法识别

## 元数据

```yaml
name: tonyenc-tonydec
category: crypto, misc, reverse, file-obfuscation
keywords:
  - TonyEnc
  - TonyDec
  - lihancong/tonyenc
  - 6688ff4f6886005611611618
  - 66 88 ff 4f 68 86 00 56 11 61 16 18
source: https://github.com/jixunmoe/tonydec
license: MIT
author: Jixun Wu
```

## 识别特征

遇到未知二进制、附件解包后文件、无正常 magic 的资源文件时，先读取文件头。
TonyEnc 的固定12字节头是：

```text
66 88 ff 4f 68 86 00 56 11 61 16 18
```

连续十六进制形式：

```text
6688ff4f6886005611611618
```

可用以下只读检查确认：

```bash
xxd -l 12 -p <文件>
```

只有完整匹配该头时才应判定为 TonyEnc；不要仅凭扩展名或乱码猜测。

## 解码算法

TonyDec 先删除12字节 TonyEnc 头。对剩余负载，从索引 `i=1` 开始，
每隔一个字节处理一次，因此只修改奇数位置。固定密钥为：

```text
9f 49 52 00 58 9f ff 23 8e fe ea fa a6 33 f3 c6
```

状态与变换：

```python
p = 0
for i in range(1, len(data), 2):
    p = (p + key[p] + i) % 16
    data[i] = data[i] ^ key[p] ^ 0xff
```

这属于固定格式的可逆混淆，不是需要口令或暴力破解的现代密码算法。

## Agent 操作流程

1. 使用 `xxd -l 12 -p` 检查头部并保留证据。
2. 命中 `6688ff4f6886005611611618` 后，优先调用已注册工具 `tonydec`：

```json
{
  "input_path": "WorkDir/.../encrypted.bin",
  "output_path": "WorkDir/.../decoded.bin"
}
```

3. 如果输入是目录，可把输入和输出都设为目录；工具会递归解码命中文件，
   并复制未命中 TonyEnc 头的普通文件。
4. 输出路径必须是新路径，工具会拒绝覆盖输入或已有文件。
5. 解码后必须使用 `file`、`xxd`、`strings`、哈希或对应格式解析器复核；
   不能仅因工具返回成功就声称已经得到 Flag 或有效载荷。
6. 若未命中固定头，停止使用 TonyDec，转回通用文件识别流程。

## 独立脚本

项目保留了 MIT 许可的上游脚本：

```bash
python Tools/third_party/tonydec/tonydec.py <input_dir> <output_dir>
```

上游命令行脚本只接受目录。Agent 在正常任务中应优先使用 `tonydec` 工具，
因为工具额外提供路径边界、防覆盖、哈希与结构化结果。

## 常见误区

- TonyEnc 与 TEA、XXTEA、AES 无关，不要套用这些算法。
- 不要丢失12字节头之后再做识别；原始头是最可靠证据。
- 解码只处理负载奇数索引，偶数位置保持不变。
- 目录中可能混有加密文件与普通文件，应逐文件判断固定头。
- 解码产物可能仍是压缩包、图片、脚本或二进制，需要继续识别其真实格式。

## 来源与许可

算法与原始脚本来源于 Jixun Wu 的 TonyDec 项目：
<https://github.com/jixunmoe/tonydec>，采用 MIT License。项目内镜像保留了
原版权声明与许可证全文。
