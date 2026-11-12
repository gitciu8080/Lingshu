---
name: mlps-assessment
description: 等保 2.0（等级保护）等级测评方法论。当任务模式为 mlps 或需要对中国网络安全等级保护第三级系统执行安全计算环境基线核查、逐项判定符合程度、产出测评报告素材时使用。覆盖身份鉴别、访问控制、安全审计、入侵防范、恶意代码防范、数据完整性保密性、剩余信息保护、个人信息保护等测评单元的核查命令与判定判例。
license: MIT
allowed-tools: Bash Read
metadata:
  user-invocable: "false"
---

# 等保 2.0 等级测评（三级安全计算环境）

## 执行原则

1. 只读核查：所有命令不得修改被测系统（无写操作、无服务重启、无配置变更）；
2. 证据先行：关键配置文件核查前先 `sha256sum` 固定；
3. 判定纪律：每个测评单元输出『单元名: 符合/部分符合/不符合』+ 命令回显；
4. 多资产：按 Orchestrator 指定的本轮资产逐台核查，报告按资产分节。

## 测评单元 → 核查命令速查（Linux 计算环境）

详细判定判例见 references/ 下分册。速查：

- 身份鉴别-a（口令策略）：`chage -l <user>`、`grep -E '^PASS_(MAX|MIN)_DAYS' /etc/login.defs`
- 身份鉴别-b（登录失败处理）：`grep -r faillock /etc/pam.d/`
- 身份鉴别-c（远程加密）：`grep -E '^(PasswordAuthentication|PermitRootLogin)' /etc/ssh/sshd_config`
- 访问控制-a（多余/特权账户）：`awk -F: '($3==0){print}' /etc/passwd`
- 访问控制-b（默认权限）：`grep -E '^umask' /etc/profile /etc/bashrc`
- 安全审计（auditd 与留存）：`systemctl is-active auditd`、`grep max_log_file /etc/audit/auditd.conf`
- 入侵防范-a（最小安装）：`rpm -qa | wc -l` / `dpkg -l | wc -l` + 非必要服务 `systemctl list-units --state=running`
- 入侵防范-b（高危端口）：`ss -tlnp`
- 恶意代码防范：`systemctl is-active clamd` / 检测进程
- 数据完整性保密性（传输加密）：`ss -tlnp | grep -E ':22|:443'`
- 剩余信息保护：`grep -E 'HISTSIZE|HISTFILESIZE' /etc/profile`

## 判定判例（节选）

- 身份鉴别-a：PASS_MAX_DAYS ≤ 90 且最小长度 ≥8 → 符合；未配置或 >180 → 不符合；有配置但弱（>90 或长度 <8）→ 部分符合
- 安全审计：auditd active 且规则非空 → 符合；安装未启用 → 部分符合；无 → 不符合
- 入侵防范-b：存在 0.0.0.0 监听的非业务高危端口（23/3389/6379 公网暴露）→ 不符合

## Windows 对象

用 `net accounts`、`secedit /export`、`auditpol /get /category:*`、`Get-Service` 等只读命令，判定逻辑同构。

## 产出

每个测评单元一行『单元名: 判定』+ 回显关键行；汇总交给 Orchestrator/Summary 生成测评报告。
