# CTF 密码学通用技巧

> 关键词:CTF,Crypto,密码学,NTRU,格密码,多项式环,SageMath,解密,公钥密码,格基,模逆,古典密码,编码
> 本文件提炼自 NCTF2023 Writeup 及通用密码 CTF 经验,以 NTRU 为例讲解格密码类题目的解密流程,并附密码题通用方法论。

## 一、NTRU 密码系统(NCTF2023 Signin)

### 系统简介

NTRU 是一种基于**格**(Lattice)困难问题的公钥密码系统,运算在截断多项式环 `Z[x]/(x^N - 1)` 上进行:

- 参数:`N`(多项式阶)、`p`、`q`(模数,q > p,通常 q 为 2 的幂)、`d`(小系数多项式权重)。
- 私钥:小系数多项式 `f`(可逆,模 q 与模 p 均有逆)。
- 公钥:`h = p * f^{-1} * g (mod q)`。
- 加密:明文多项式 `m`(0/1 系数)选随机小多项式 `r`,密文 `e = r*h + m (mod q)`。

### 解密原理

接收方用私钥 `f` 计算 `a = f * e (mod q)`,则:

```
a = f*(r*h + m) = r*p*g + f*m (mod q)
```

由于 `f、g、r、m` 都是小系数多项式,`a` 的系数不会 wrap around(落在 `(-q/2, q/2]`),故先在整数范围内恢复 `a`,再模 p 消去 `r*p*g` 项:

```
m = f^{-1} * a (mod p)
```

### 解密流程(SageMath)

```python
# 题目给出:N、p、q、d、私钥 fx、公钥 hx、密文 e
N, p, q = 509, 3, 512

# 1. a = f * e mod (x^N - 1),系数对称化到 (-q/2, q/2]
Rq.<x> = PolynomialRing(Zmod(q))
f = Rq(fx)
c = Rq(e)
Modq = x^N - 1
a = (f * c) % Modq
A = [int(i) for i in a]
for i in range(len(A)):
    if A[i] > q // 2:          # q/2 = 256
        A[i] -= q

# 2. 在模 p 环中求 f 的逆
Rp.<x> = PolynomialRing(Zmod(p))
f = Rp(fx)
Mod = x^N - 1
Fp = inverse_mod(f, Mod)

# 3. m = Fp * a mod (x^N - 1),系数为 0/1
b = sum(A[i] * x^i for i in range(len(A)))
m = (Fp * b) % Mod

# 4. 每 8 位一组转 ASCII
flag = ''.join(
    chr(int(''.join(str(i) for i in m[j*8:(j+1)*8]), 2))
    for j in range(len(m)//8)
)
print(flag)   # NCTF{0e301384-a06c-11ee-959d-b39f60b9e252}
```

### 要点

- **系数对称化**是解密关键:模 q 结果要映射到 `(-q/2, q/2]`,否则后续模 p 会出错;
- 多项式求逆用 SageMath 的 `inverse_mod(f, Mod)`(需 f 可逆;不可逆时换参数或重试);
- NTRU 类 CTF 题通常给全参数,直接按解密流程实现即可;
- 相关理论:08-密码学与身份认证/密码学基础.md(公钥密码部分)。

## 二、格密码(Lattice)类题目通用思路

| 题型 | 思路 | 工具 |
| --- | --- | --- |
| NTRU | 私钥解密:a = f*e mod q → 对称化 → 模 p 求逆 → 明文 | SageMath |
| LWE/LWR | 用格基约简(BKZ/LLL)解带误差线性方程组;已知噪声分布时可用对偶攻击 | SageMath、fpylll |
| 背包密码 | 超递增背包可贪心解;非超递增用 LLL 找短向量(子集和问题) | SageMath |
| RSA 变体 | 共模/低指数/小公因数/已知 p±q/Coppersmith 求小根 | SageMath small_roots、RsaCtfTool |
| DLP/ECC | 小阶群 Pohlig-Hellman、Pohlig 分解、Smart 攻击(异常曲线)、MOV | SageMath |
| 哈希长度扩展 | 经典长度扩展攻击构造合法消息 | hashpump |

格密码通用武器:
- `LLL`/`BKZ` 格基约简;
- 构造格把目标问题化为"找短向量/最近向量"(SVP/CVP);
- SageMath 的 `IntegerLattice`/`BKZ` 接口。

## 三、古典密码与编码速查

| 类型 | 特征 | 破解思路 |
| --- | --- | --- |
| 凯撒/维吉尼亚 | 字母频次、位移 | 频次分析、`quipqiup`、维吉尼亚 Kasiski 测试 |
| 摩斯电码 | `.` `-` 与分隔 | 直接转写 |
| 培根密码 | 5 位一组二进制 | 按表还原 |
| Base 系列 | `=` 填充、字母表 | 识别进制逐步解码(CyberChef) |
| 栅栏/转置 | 重排 | 按行/列组合尝试 |
| 仿射/替换 | 字母映射 | 频次 + 已知明文攻击 |

工具:CyberChef(万能编码转换)、quipqiup(替换密码)、dcode.fr(古典密码全集)、SageMath(数学密码)。

## 四、密码题通用方法论

1. **识别算法**:看密文格式、参数名称、脚本特征(RSA 的 n/e、AES 的 iv/key、NTRU 的 N/p/q/d、LWE 的 A/b/模)。
2. **找已知条件**:题目常给"该给的参数都给了",全部参数 → 直接实现解密流程;部分缺失 → 找数学关系补足。
3. **小参数优先**:参数过小(如 RSA 小 n 可分解、EC 小阶)直接爆破/分解。
4. **实现工具选型**:
   - SageMath:多项式环、有限域、格、数论一站式;
   - Python(pyCrypto/gmpy2):常规 RSA/AES;
   - RsaCtfTool:常见 RSA 攻击自动化;
   - CyberChef:编码与古典密码。
5. **验证**:解密结果应符合 flag 格式(`NCTF{...}`/`flag{...}`),按格式反向确认。

## 合规声明

密码学破解技术仅用于 CTF 题目、自有数据或授权安全测试;请勿用于破解他人系统与数据。
