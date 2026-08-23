# 字典库(导入自旧智能体知识库)

> 关键词:字典,密码字典,弱口令,用户名,目录扫描,端口,DNS,子域名字典,爆破,brute-force,常用密码,用户名枚举,Web目录,API参数,密码规则
> 本模块整合自旧智能体知识库 `G:\WorkDir\.RAG.old\Dic\`,包含渗透测试常用的各类爆破与枚举字典(共 291 个文件,约 35 MB)。

## 来源说明

- 原目录:旧知识库 `Dic/`(字典集合)
- 适配:原样复制全部子目录与文件;保留 `_meta.yaml` 元数据与各目录 `readme.md`

## 目录导航

| 目录 | 内容 | 典型文件 |
| --- | --- | --- |
| `auth/password/` | 密码字典:top10~top100000、复杂组合、WPA 字典 | `password-top100000.txt`(805KB)、`wpa/top200000-wpa.txt`(2.1MB) |
| `auth/username/` | 用户名:中文邮箱/手机号/拼音姓名/top10000 | `cn-fullname-14k.txt`、`username-top10000.txt` |
| `auth/credential-pair.txt` | 常见账号密码对 | - |
| `network/` | DNS 服务器、本地 IP、排除列表 | - |
| `port/` | 端口清单 + 各服务(ssh/rdp/mysql/oracle/redis 等)默认口令与用户字典 | `port-list.md`(249KB 端口知识)、`port.txt` |
| `regular/` | 规则字典:地址(行政区划)、字母组合、数字、SEO 词 | `letter/lower-4char.txt`(2.2MB)、`number/birthday.txt`(962KB) |
| `web/api-param/` | API 参数名(通用/回调/验证码/登录等) | `param-extended.txt`(526KB)、top100 参数 |
| `web/cms/` | CMS 相关(thinkphp/wordpress) | - |
| `web/directory/` | Web 目录字典:asp/aspx/jsp/php/js/二级目录 | `main.txt`(370KB)、`jsp/do.txt`(529KB)、`php/php.txt`(655KB) |
| `web/dns/` | 子域名字典 | `dns.txt`(1.2MB) |
| `web/file-backup/` | 备份文件/敏感文件后缀字典 | `misc.txt`(553KB) |
| `web/http/` | HTTP 头、User-Agent、方法、MIME | `top500-user-agent.txt` |
| `web/middleware/` | 中间件(shiro 密钥库 2.5MB、spring、tomcat、weblogic、rabbitmq) | `shiro/key.txt`(2.5MB) |
| `web/service/` | 服务(druid/phpmyadmin/xxljob/jira) | - |
| `web/upload/` | 上传后缀与 content-type | - |
| `web/webshell/` | WebShell 目录与密码字典 | `webshell-pass.txt`(3.5MB) |
| `web/ctf/` | CTF 专用参数/SQL/URI | - |

## 密码规则(源自原 readme)

### 常见组合 (Common)

- `payload` + 123 / 1234 / 123456 / 12345 / @123 / @123456 / @12345 / #123 / #123456 / #12345 / _123 / _123456 / _12345
- `payload` + 123!@# / !@#$ / !@# / ~!@ / !@#123
- `payload` + 2017 / 2016 / 2015 / @2017 / @2016 / @2015

### 生日组合 (Birthday)

- `19880808`、`tony19980808`、`tony@19980808`

### 年份列表 (years)

- 1987、1988、1989 ...

### 1337 模式替换 (leet)

- `1earn` 等字母数字替换

### 键盘布局 (Keyboard layout)

- `qwerty` 等键盘序列

### 大小写变换 (case reversal)

- admin / Admin / admIn

### 姓名全拼 / 带点

- zhangsan / jing.zhang

### 单位名组合 (company + sth.)

- `Huawei@123`(单位名+@+年份/123/常见弱口令)
- `BEIJINGXXyy@2019`(单位名+小写业务名+@+年份)
- `BEIJINGinfo@2019`(大写地名+小写业务名+@+年份)
- `BJ_cy_yey`(大写城市+小写区县+单位名,如北京_朝阳_幼儿园)
- `tony@2019`(管理员名+@+年份)
- `0000-9999`(工号)
- `wy@360buy`、`xxx.com@123`、`企业缩写@2021`(域名+简称)

## 使用建议

- **爆破**:配合 `06-安全工具/密码破解工具.md`(hashcat/john/hydra)使用
- **目录扫描**:配合 `06-安全工具/信息收集工具.md`(ffuf/gobuster/dirsearch)使用
- **Shiro 检测**:`web/middleware/shiro/key.txt` 为密钥库,配合 Shiro 利用工具
- **字典量大**:注意部分文件超 1MB,勿整库灌入 RAG 向量库,作为工具资源引用
- 各目录 `_meta.yaml` 描述字段含义与适用范围
- 大文件编辑工具:[PilotEdit](https://www.pilotedit.com/)、[glogg](https://glogg.bonnefon.org/download.html)

## 合规声明

字典用于授权测试环境;未授权爆破属违法行为。
