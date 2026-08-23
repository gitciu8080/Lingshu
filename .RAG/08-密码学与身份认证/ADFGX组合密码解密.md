# ADFGX、纵向栅栏与凯撒组合密码的识别和解密

> 关键词:ADFGX,波利比奥斯方格,Polybius,栅栏密码,rail-fence,凯撒密码,Caesar,组合密码,CTF解密,列置换

## 适用场景

当密文具有以下特征时，应优先检查 ADFGX，而不是仅根据附件名将题目判断为
PWN 或逆向：

- 密文字符集严格或近似限制在 `A/D/F/G/X`；
- 去除空白后的长度为偶数，可以两字符组成一个坐标；
- 五种字符的分布较均匀，信息熵接近 `log2(5)`；
- 附件只是短 ASCII 文本，没有 ELF、PE、脚本或固件特征。

标准 ADFGX 把 `A/D/F/G/X` 同时作为 5×5 Polybius 方阵的行列标签。每两个
密文字符对应方阵中的一个明文字母。标准算法通常还包含列置换，但组合题可能
删除、替换或再次叠加其他换位与移位步骤，不能假设解出方阵坐标后就是最终明文。

## 第一阶段：ADFGX 坐标解码

给定 25 字母方阵字符串 `alphabet`，按行填入 5×5 方阵；通常需要合并 `I/J`。
本知识来源会话使用的题目特定方阵为：

```text
phqgmeaynofdxkrcvszwbutil
```

该值不是 ADFGX 通用常量。处理新题时应从题目提示、题名、已知明文或密钥搜索
中重新确认。

```python
def decode_adfgx(cipher: str, alphabet: str) -> str:
    labels = "ADFGX"
    alphabet = alphabet.lower().replace("j", "")
    if len(alphabet) != 25 or len(set(alphabet)) != 25:
        raise ValueError("ADFGX 方阵必须包含 25 个不重复字母")

    square = [alphabet[row * 5:(row + 1) * 5].upper() for row in range(5)]
    lookup = {
        labels[row] + labels[col]: square[row][col]
        for row in range(5)
        for col in range(5)
    }
    normalized = "".join(cipher.split()).upper()
    if len(normalized) % 2 or set(normalized) - set(labels):
        raise ValueError("密文不是有效的 ADFGX 坐标流")
    return "".join(
        lookup[normalized[index:index + 2]]
        for index in range(0, len(normalized), 2)
    )
```

如果坐标解码结果长度正确但不可读，应依次检查：

1. 方阵字母顺序是否正确；
2. 是否需要按关键字撤销标准列置换；
3. 题目是否明确表示关键字为空，即没有 ADFGX 列置换；
4. 中间文本是否还叠加了栅栏、列换位、凯撒或词元替换。

## 第二阶段：区分两类"栅栏"

不要只尝试常见的 W 形 Rail Fence。本类题使用的 `traditional_fence` 实际是：

1. 把中间串依次切成 `depth` 个近等长行；
2. 前 `len(text) % depth` 行多一个字符；
3. 再按列从上到下读取这些行。

```python
def vertical_fence(text: str, depth: int) -> str:
    if depth < 2 or depth > len(text):
        raise ValueError("非法栅栏深度")

    base, remainder = divmod(len(text), depth)
    lengths = [base + (row < remainder) for row in range(depth)]
    rows, offset = [], 0
    for length in lengths:
        rows.append(text[offset:offset + length])
        offset += length

    return "".join(
        rows[row][column]
        for column in range(max(lengths))
        for row in range(depth)
        if column < len(rows[row])
    )
```

建议同时枚举以下两种变体并分别标注结果，避免术语歧义：

- W 形往返轨道栅栏；
- 上述"近等长行切分后纵向读取"的简单列换位。

## 第三阶段：枚举栅栏深度和凯撒移位

对每个合理深度枚举 26 个凯撒位移，以已知格式、语言得分和可打印性排序。
来源会话最终命中的题目特定参数是简单纵向栅栏 `depth=8`、凯撒
`shift=16`，但新题必须重新枚举，不能硬编码。

```python
def caesar(text: str, shift: int) -> str:
    return "".join(
        chr((ord(char) - 65 + shift) % 26 + 65)
        if "A" <= char <= "Z" else char
        for char in text.upper()
    )


def search_candidates(intermediate: str, markers=("FLAG", "CTF", "CISCN")):
    candidates = []
    upper_bound = min(48, len(intermediate))
    for depth in range(2, upper_bound + 1):
        transposed = vertical_fence(intermediate, depth)
        for shift in range(26):
            plaintext = caesar(transposed, shift)
            hits = [marker for marker in markers if marker in plaintext]
            if hits:
                candidates.append((depth, shift, hits, plaintext))
    return candidates
```

没有明显格式标记时，可以加入四元组频率、字典覆盖率、可打印字符比例等评分，
但评分只能用于排序，不能替代最终验证。

## 第四阶段：机械词元映射

组合题可能故意把花括号和数字编码为英文词元。例如：

```text
brace -> { 或 }
one   -> 1
two   -> 2
...
nine  -> 9
```

来源会话还使用了题目特定映射 `yero -> 0`。这可能看起来像 `zero` 的拼写
错误，但应忠实执行题目或参考脚本定义的映射，不要擅自做语义纠错。若首尾都由
`brace` 表示，可先全部替换为 `{`，再把末尾的 `{` 确定性改为 `}`。

映射表必须采用从题面或代码中得到的确切顺序；替换后保留每一步中间值，避免
短词元在长词元内部产生意外替换。

## 推荐工作流

1. 规范化密文并验证字符集、偶数长度和坐标对数量；
2. 用题目证据确认 25 字母方阵，执行 ADFGX 坐标解码；
3. 分别尝试标准列置换、W 形栅栏和简单纵向栅栏；
4. 枚举合理深度与全部凯撒位移，用格式标记和语言得分筛选；
5. 严格按题目定义执行词元到符号/数字的机械映射；
6. 验证括号平衡、格式、长度和中间结果，保留参数与脚本输出作为证据；
7. 仅在获得授权时进行平台校验，不把候选格式当作已经成功。

## 常见失败原因

- 根据附件名误判为 PWN，没有先检查文件真实类型和字符集；
- 把所有"栅栏"都理解成 W 形往返轨道；
- 盲目使用标准 ADFGX 列置换，而题目实际没有该步骤；
- 在不知道方阵时直接暴力枚举后续参数；
- 对疑似拼写错误做语义修正，偏离参考脚本的机械映射；
- 只看到类似 Flag 的文本就宣布成功，没有核验完整解密链和输出格式。

## 知识边界

本文只沉淀通用算法和已验证的题型特征，已移除来源会话的目标路径、附件哈希、
平台编号及最终 Flag。方阵、深度、位移和词元映射均可能是题目特定参数，使用时
必须以当前附件证据重新验证。

## 来源元数据

```yaml
type: algorithm_knowledge
category: crypto
tags:
  - ADFGX
  - Polybius-square
  - transposition
  - rail-fence
  - Caesar
  - CTF
source: sanitized-session-aa87d0e4
sensitivity: sanitized
```
