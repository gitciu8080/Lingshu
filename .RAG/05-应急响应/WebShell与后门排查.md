# WebShell 与后门排查(WebShell & Backdoor Investigation)

> 关键词:WebShell,一句话木马,大马,内存马,后门,排查,上传漏洞,图片马,文件扫描,代码审计,日志回溯,计划任务,开机启动,注册表,authorized_keys,rootkit,Java Agent,Filter,清除修复,文件监控,WAF,持久化

## 一、WebShell 常见类型

WebShell 是攻击者上传到 Web 服务器的恶意脚本,用于远程控制。按形态分三类:

| 类型 | 特征 | 典型形态 | 危害 |
| --- | --- | --- | --- |
| 一句话木马(小马) | 极短代码,配合客户端(蚁剑/冰蝎/哥斯拉)连接 | `<?php @eval($_POST['x']);?>`、`<%execute(request("x"))%>` | 隐藏性好,可执行任意命令 |
| 大马(完整马) | 功能完整的网页管理面板 | 文件管理、数据库管理、命令执行、提权模块 | 直接控制服务器 |
| 内存马 | 无文件落地,驻留内存(Java 容器常见) | Servlet/Filter/Listener 注入、Agent 注入 | 磁盘扫描不到,难发现 |

**常见混淆/隐藏手法**:编码(URL 编码、Base64、Hex)、加密流量(冰蝎/哥斯拉加密通信)、图片马(图片尾部追加代码)、属性隐藏、时间戳篡改、植入合法文件中。

## 二、WebShell 常见落点

- **上传目录**:`upload/`、`uploads/`、`attachments/`、`images/`(最常见的落地位置)
- **备份/临时目录**:`backup/`、`temp/`、`tmp/`、`cache/`(常被攻击者利用做中转)
- **图片马**:`/upload/images/xxx.jpg`(图片后追加 PHP/ASP 代码,结合解析漏洞)
- **编辑器/附件目录**:FCKeditor、UEditor、KindEditor 等编辑器上传目录
- **静态资源目录伪装**:`/static/`、`/assets/`、`/js/` 下的 .php/.jsp/.aspx 文件
- **CMS 目录**:WordPress `wp-content/uploads/`、DedeCMS、ThinkPHP 等框架的 runtime 目录
- **被篡改的合法文件**:在 index.php、common.php 等正常文件末尾追加恶意代码

## 三、排查方法(Detection)

**1. 文件特征扫描(最直接)**:

- 用 WebShell 查杀工具:河马 WebShell 查杀(shellpub.com)、D 盾、深信服 WebShell 查杀、CloudWalker(牧云)等
- 编写 YARA 规则匹配常见特征:`eval($_POST`、`assert(`、`base64_decode(`、`gzinflate(`、`create_function(`、`preg_replace('/.*/e'`、`system(`、`shell_exec(`、`passthru(`、`@$_REQUEST`、`eval(base64_decode` 等
- 扫描命令示例(Linux):
  ```bash
  # 查找最近 7 天修改的 PHP 文件
  find /var/www -name "*.php" -mtime -7 -type f
  # 搜索可疑函数调用
  grep -rl -E "eval\(|assert\(|base64_decode\(|gzinflate\(|system\(|shell_exec\(" /var/www --include="*.php"
  # 查找图片后缀的脚本内容(图片马)
  find /var/www -name "*.jpg" -type f -exec grep -l "<?php" {} \;
  ```
- Windows 下可用 Everything 按修改时间排序,结合 PowerShell 批量检索内容

**2. 按修改时间排查**:

- 对比文件系统时间线:重点关注攻击时间窗口内被修改/新建的脚本文件
- 注意攻击者可能用 `touch -t` 篡改时间戳,结合 inode 变更时间(ctime)判断:`stat 文件名` 查看 Birth/Ctime
- 用文件监控记录(如 `auditd`、`osquery`)回溯历史变更

**3. 代码审计特征(人工确认)**:

- 逐个检查高危函数上下文:`eval`、`assert`、`system`、`exec`、`popen`、`proc_open`、`shell_exec`、`passthru`、`$_GET/$_POST/$_REQUEST` 直接进入函数参数
- 检查文件头尾:被追加代码的合法文件,末尾常有异常闭合标签或代码
- 检查加密/混淆代码:超长 Base64、编码字符串、动态函数调用 `$_REQUEST['f'](...)`
- 检查文件权限异常:Web 目录出现可写脚本、属主异常

**4. 日志回溯(找上传记录)**:

- Web 访问日志(Nginx `access.log` / Apache `access_log`):检索可疑上传请求
  ```bash
  grep -iE "upload|\.php.*(POST|PUT)" /var/log/nginx/access.log | grep -vE "正常白名单"
  # 检索访问可疑文件的记录
  grep -E "shell\.php|\.jsp.*upload|eval" /var/log/nginx/access.log
  ```
- 检索异常 UA、异常频率、图片路径返回 200 且后续紧跟 .php 请求(上传后访问)
- 查看访问时间集中的异常 IP;结合 WAF 日志找上传与命令执行尝试
- 数据库审计日志:检查是否通过 SQL 注入写入文件

## 四、常见系统后门与持久化(Persistence)

WebShell 只是入口,攻击者通常还会留持久化后门:

| 持久化方式 | 检查方法(Linux) | 检查方法(Windows) |
| --- | --- | --- |
| 计划任务 | `crontab -l`、`/etc/cron.d/`、`/var/spool/cron/` | `schtasks /query /fo LIST /v`、任务计划程序 |
| 开机启动 | `systemctl list-unit-files`、`/etc/rc.local`、`/etc/init.d/`、`~/.bashrc`、`~/.profile` | 注册表 Run 键、启动文件夹、服务 |
| 服务 | `systemctl list-units`、`/etc/systemd/system/` | `services.msc`、`sc query`、`reg query HKLM\SYSTEM\CurrentControlSet\Services` |
| 注册表 | — | `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"`、`HKLM\...\Run`、`RunOnce`、`Image File Execution Options` |
| SSH 后门 | 检查 `~/.ssh/authorized_keys` 是否有陌生公钥;`/etc/ssh/sshd_config` 是否被改 | — |
| rootkit | `chkrootkit`、`rkhunter`、比对 `ps` 与 `/proc`、检查内核模块 `lsmod` | 驱动级 rootkit 需专杀工具 |
| 其他 | 动态链接库劫持 `ld.so.preload`、`/etc/ld.so.preload`;WMI 事件订阅 | WMI 事件订阅 `wmic /namespace:\\root\subscription` |

**通用排查命令**:

```bash
# Linux:查看所有登录会话与异常连接
w; last -a; lastlog
# 查看监听端口与对应进程
ss -antlp; lsof -i -P -n
# 查找最近修改的可疑可执行文件
find / -type f -perm /111 -mtime -7 2>/dev/null
```

```powershell
# Windows:查看计划任务与启动项
schtasks /query /fo CSV | ConvertFrom-Csv | Where-Object {$_.TaskName -notlike 'Microsoft*'}
Get-CimInstance Win32_StartupCommand
# 查看监听端口与进程
netstat -ano | findstr LISTENING
```

## 五、内存马排查(Java 环境重点)

Java 内存马(注入 Servlet/Filter/Listener/Controller 或通过 Agent 注入)无文件落地,是排查难点。

**排查思路**:

- **进程排查**:`jps -l`、`ps -ef | grep java` 查看异常 Java 进程;对比基线
- **网络连接排查**:`netstat -antlp | grep java` 查看 Java 进程异常外联(与 C2 通信)
- **Java Agent 排查**:检查 JVM 启动参数是否被注入 `-javaagent`;`jinfo`、`jcmd` 查看加载的 agent;检查 `javaagent` 相关 jar 与日志
- **Filter/Servlet 排查**:连接 JVM 查看已注册的 Filter/Servlet(`jmap -histo` 查可疑类),重点看:
  - 是否新增了非业务定义的 Filter/Servlet
  - Spring 容器中异常的 Bean/Handler
  - `WebApplicationContext` 中动态注册的组件
- **工具**:使用 Java 内存马检测工具(如 Landgrey 的 inject 检测脚本、`java-memshell-scanner` 项目)辅助
- **配合层**:内存马常与反序列化漏洞(如 Fastjson、Shiro、Log4j)结合,排查对应组件版本与利用痕迹

**处置**:内存马无法直接删除文件,需重启 Java 应用(重启前先确认无磁盘持久化,否则重启后仍在);或在代码层移除动态注册逻辑。

## 六、清除与修复(Remediation)

1. **隔离**:先断网/隔离失陷主机,防止攻击者继续利用
2. **备份证据**:复制 WebShell 样本、相关日志到安全位置,记录哈希
3. **删除 WebShell**:移除所有确认的恶意文件;对可疑文件先重命名隔离再确认
4. **清除持久化**:删除计划任务/服务/注册表/authorized_keys 中的后门;清理内存马需重启应用
5. **重置凭据**:修改 Web 应用账号、数据库口令、服务器口令、FTP/管理后台口令
6. **修补入口**:修复上传漏洞(校验文件类型/内容、随机化文件名、上传目录禁止执行脚本)、修补框架漏洞、清理弱口令
7. **验证**:再次全盘扫描确认干净;观察期监控异常访问与文件变更

## 七、预防(Prevention)

- **上传校验**:白名单校验扩展名与 MIME、校验文件头内容、随机化存储文件名、上传目录设置禁止执行脚本(`php_admin_flag engine off`、Nginx `location` 限制)
- **WAF**:部署 WAF 拦截 WebShell 上传与命令执行特征;开启日志留存
- **文件监控**:部署文件完整性监控(如 `Tripwire`、`osquery`、`auditd`、云主机安全 Agent),对 Web 目录与系统关键目录变更实时告警
- **代码与依赖安全**:上线前代码审计、依赖组件漏洞扫描、禁用危险函数(如 `disable_functions` 配置)
- **最小权限**:Web 服务低权限运行、目录权限收紧、数据库与应用分离
- **日志与监控**:Web 日志集中留存、访问异常(上传后立即访问、命令执行特征)告警

## 八、排查处置速查清单(Checklist)

收到"网站被挂马/服务器可疑"报告后,按以下顺序执行:

- [ ] 1. **隔离**:确认主机后立即断网/隔离,防止攻击者继续利用与扩大影响
- [ ] 2. **保全证据**:复制 WebShell 样本、相关日志(access.log、secure/auth.log、数据库审计日志)到安全目录,记录哈希
- [ ] 3. **全盘扫描**:河马/D盾/CloudWalker 等工具扫描 Web 目录,记录命中文件
- [ ] 4. **按时间排查**:找出攻击时间窗口内新建/修改的脚本文件(结合 ctime,防时间戳伪造)
- [ ] 5. **人工审计**:对可疑文件逐个看代码,确认恶意性(高危函数、混淆、加密)
- [ ] 6. **日志回溯**:从 access.log 回溯上传请求与访问记录,定位攻击者 IP 与上传时间
- [ ] 7. **查系统后门**:计划任务、启动项、服务、注册表、authorized_keys、rootkit
- [ ] 8. **查内存马**:Java 环境检查 agent/Filter/Servlet 注入
- [ ] 9. **清除**:删除 WebShell 与后门,清理持久化,重置凭据
- [ ] 10. **封堵入口**:修上传漏洞、框架漏洞,加固配置,部署 WAF
- [ ] 11. **验证**:复扫确认干净,观察期监控文件变更与异常访问
- [ ] 12. **复盘**:记录时间线、输出事件报告、沉淀 IOC 到检测规则

## 九、典型案例排查思路

**场景 A:图片目录出现 jpg 但被当作 PHP 执行**

- 排查:确认 Web 服务器是否存在解析漏洞(如 Nginx + PHP-FPM 配置不当、Apache 多后缀解析);检查图片尾部是否追加 PHP 代码;回溯上传日志找到上传者 IP 与利用时间
- 处置:修复解析配置、上传目录禁止脚本执行、删除恶意图片马

**场景 B:合法 PHP 文件被追加代码(隐蔽后门)**

- 排查:用文件完整性基线(FIM)对比变更;`grep` 文件末尾异常代码;检查文件 mtime/ctime 与属主变化
- 处置:从版本库还原文件、加固文件权限、部署文件监控

**场景 C:内网主机反复中毒(持久化未清除)**

- 排查:检查计划任务/服务/注册表/WMI 订阅等持久化点;检查攻击者是否留了备用后门;排查是否有域内批量投放通道(GPO、分发软件)
- 处置:彻底清持久化 + 封堵投放通道 + 重置全部相关凭据

**场景 D:杀软扫不到但行为异常(内存马)**

- 排查:磁盘扫描无结果时转向进程、网络连接、JVM 内部组件排查;结合反序列化漏洞利用痕迹定位
- 处置:重启应用清除内存马(先确认无磁盘持久化),修补反序列化漏洞
