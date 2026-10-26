"""评分制题型分类模块。

关键词作为弱证据（每命中 +1 分），文件内容信号权重更高（+5~+15 分）。
分类只产生一次正式结果写入 MissionState，Attack 不自行重新分类。
支持初始分类（initial）和后侦察二次分类（post_recon）。
"""
from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass, field
from typing import Literal

from Tools.target import TargetKind, TargetSpec

# 短英文关键词（≤4 个 ASCII 字母）必须词边界匹配，防止 "ai" 命中
# "aicreate"、"des" 命中 "desktop" 等误报。
_SHORT_ASCII_KEYWORD_RE = re.compile(r"^[A-Za-z]{1,4}$")


def _keyword_matches(keyword: str, text: str) -> bool:
    """关键词匹配：短英文关键词按词边界，其余按子串。"""
    if _SHORT_ASCII_KEYWORD_RE.fullmatch(keyword):
        return re.search(rf"\b{re.escape(keyword)}\b", text) is not None
    return keyword in text

# ---------------------------------------------------------------------------
# 题型标识
# ---------------------------------------------------------------------------

CategoryName = Literal[
    "web", "pwn", "reverse", "crypto", "forensics",
    "malware", "misc", "osint", "ai-ml", "unknown",
]

ALL_CATEGORIES: list[CategoryName] = [
    "web", "pwn", "reverse", "crypto", "forensics",
    "malware", "misc", "osint", "ai-ml",
]

# 关键词权重（弱信号，每命中 +1）
_KEYWORD_WEIGHTS: dict[CategoryName, list[str]] = {
    "web": [
        "web", "http", "sqli", "xss", "ssrf", "csrf",
        "注入", "跨站", "请求伪造", "远程代码执行",
        "web 应用", "web application",
    ],
    "pwn": [
        "pwn", "rop", "溢出", "overflow", "heap", "shellcode",
        "二进制利用", "栈溢出", "堆利用", "格式化字符串",
        "rop 链", "ret2libc", "aslr", "nx", "canary",
        "binary exploitation",
    ],
    "reverse": [
        "reverse", "逆向", "反编译", "脱壳", "crackme",
        "reverse engineering", "ida", "ghidra", "汇编",
        "x86", "arm", "mips", "字节码", "unpack",
    ],
    "crypto": [
        "crypto", "密码", "加密", "cipher", "rsa", "aes",
        "encrypt", "decrypt", "公钥", "私钥", "哈希",
        "古典密码", "vigenere", "caesar", "des", "ecc",
    ],
    "forensics": [
        "forensics", "取证", "memory", "内存", "disk", "磁盘",
        "pcap", "网络包", "volatility", "autopsy",
        "镜像", "扇区", "stego", "隐写", "exif",
        "memory dump", "磁盘镜像",
    ],
    "malware": [
        "malware", "恶意软件", "sandbox", "病毒", "木马",
        "c2", "后门", "勒索软件", "pe 文件", "dll",
        "进程注入", "malware analysis",
    ],
    "misc": [
        "misc", "杂项", "linux 提权", "bash", "python jail",
        "dns", "编码", "games", "沙箱逃逸",
        "pyjail", "bashjail", "rf", "sdr",
    ],
    "osint": [
        "osint", "开源情报", "geolocation", "定位",
        "social media", "图片定位", "元数据",
        "whois", "subdomain",
    ],
    "ai-ml": [
        "ai", "机器学习", "adversarial ml", "llm attack",
        "prompt injection", "模型窃取", "对抗样本",
        "model poisoning",
    ],
}

# 文件类型检测信号（强信号，高分值）
# 注意：ELF 特征不在此表 —— ELF 是 pwn 与 reverse 的共同载体，归属需按
# "是否伴随远程服务线索" 条件判定（见 _attribute_elf_signals）。
_FILE_TYPE_SIGNALS: dict[str, list[str]] = {
    "reverse": ["Mach-O", "PE32", "DEX", "Java class", "WASM", "APK"],
    "forensics": ["pcap", "pcapng", "tcpdump", "PCAP", "PCAPNG"],
    "malware": ["PE32+", "Microsoft executable"],
    "misc": ["Python script", "ASCII text"],
}

# ELF 文件特征（file 魔法输出片段与扩展名）：单独收集后条件归属。
_ELF_FILE_TYPE_SIGNALS: list[str] = [
    "ELF", "executable, x86", "LSB executable", "ELF 64-bit",
]
_ELF_EXTENSIONS: list[str] = [".elf"]

# 远程服务连接线索：nc/ncat host port、host:port 连接提示等。
# CTF 惯例：pwn 题（二进制利用）会提供远程服务；逆向题只给单文件。
_REMOTE_SERVICE_RE = re.compile(
    r"\bnc(?:at)?\s+[a-z0-9.\-]+\s+\d{1,5}\b"          # nc 1.2.3.4 8888
    r"|\b(?:telnet|ssh|连接|攻击)\s*(?:远程|目标)?\s*[a-z0-9.\-]+:\d{1,5}\b"
    r"|\bremote\s+(?:service|server|instance)\b"
    r"|(?:远程|remote)[^\n]{0,12}(?:服务器|服务|地址|端口)"
    r"|[a-z0-9.\-]+:\d{4,5}\s*(?:端口|连接)",
    re.IGNORECASE,
)

# ELF 存在时的辅助偏置（弱于文件信号）。libc/ld 附件是 ret2libc 类
# pwn 题的标志性提供物，权重与文件信号持平。
_PWN_BIAS_RE = re.compile(r"\blibc\b|\bld-linux\b|\bld\.[-\w]*linux|ret2libc", re.IGNORECASE)
_REVERSE_BIAS_RE = re.compile(
    r"\bupx\b|packed|加壳|脱壳|\blicense\b|\bkeygen\b|注册码|序列号|crackme",
    re.IGNORECASE,
)

# 文件类型信号权重
_FILE_SIGNAL_WEIGHT = 10
# ELF 辅助偏置权重：libc 偏置 = 文件信号级；加壳/注册类偏置 = 弱偏置
_ELF_PWN_BIAS_WEIGHT = 10
_ELF_REVERSE_BIAS_WEIGHT = 6

# 扩展名强信号：独立于题面文本，文件类型证据优先于弱关键词
# （.elf 已移入 _ELF_EXTENSIONS 条件归属）
_EXTENSION_SIGNALS: dict[str, list[str]] = {
    "reverse": [".exe", ".dll", ".apk", ".dex", ".class", ".wasm", ".so", ".ko"],
    "forensics": [
        ".pcap", ".pcapng", ".raw", ".img", ".dd", ".mem", ".vmem",
        ".dmp", ".lime", ".hiber", ".hpak", ".vmss", ".vmsn",
    ],
    "crypto": [".pem", ".key", ".cer", ".crt", ".asc", ".gpg"],
    "misc": [".py", ".js", ".sh", ".jar", ".tar", ".zip", ".gz"],
}

# 文件名关键词权重
_FILENAME_WEIGHT = 5

# 目标类型默认分类
_TARGET_KIND_DEFAULTS: dict[TargetKind, list[CategoryName]] = {
    "network": ["unknown"],    # 网络目标不预设 web
    "archive": ["unknown"],
    "single_file": ["unknown"],
    "directory": ["unknown"],
}


# ---------------------------------------------------------------------------
# CategoryDecision
# ---------------------------------------------------------------------------


@dataclass
class CategoryDecision:
    """题型分类决策 — 单一事实来源。

    Attrs:
        primary: 主要题型。
        secondary: 候选次要题型列表。
        confidence: 置信度 (0-1)。
        scores: 每个候选题型得分。
        evidence: 分类证据列表。
        stage: 分类阶段（initial / post_recon / manual）。
    """

    primary: CategoryName
    secondary: list[CategoryName] = field(default_factory=list)
    confidence: float = 0.0
    scores: dict[str, float] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    stage: Literal["initial", "post_recon", "manual"] = "initial"

    @property
    def selected(self) -> list[CategoryName]:
        """返回所有应加载 Skill 的题型列表（primary + secondary）。"""
        result = [self.primary] if self.primary != "unknown" else []
        for cat in self.secondary:
            if cat not in result:
                result.append(cat)
        return result


@dataclass(frozen=True)
class ReconSignal:
    """从 Recon 原文中确定性提取、可写入 Fact 的结构化信号。"""

    category: CategoryName
    content: str
    score: float
    confidence: float


@dataclass
class ReclassificationResult:
    """二次分类提案及系统接受/拒绝结果。"""

    candidate: CategoryDecision
    accepted: bool
    reason: str
    signals: list[ReconSignal] = field(default_factory=list)
    evidence_fingerprint: str = ""


# ---------------------------------------------------------------------------
# 分类函数
# ---------------------------------------------------------------------------


def _attribute_elf_signals(
    scores: dict[str, float],
    evidence: list[str],
    *,
    elf_hits: list[str],
    context_text: str,
    source: str = "",
    weight: float = _FILE_SIGNAL_WEIGHT,
) -> None:
    """ELF 证据的条件归属：伴随远程服务线索 → pwn，否则 → reverse。

    CTF 惯例：pwn 题（二进制利用）在 ELF 之外还会提供 nc/远程服务地址；
    逆向题通常只给一个可执行文件。辅助偏置：libc/ld 附件偏 pwn，
    加壳/license/序列号特征偏 reverse（仅在 ELF 证据存在时生效）。
    """
    if not elf_hits:
        return
    lowered = context_text.lower()
    if _REMOTE_SERVICE_RE.search(lowered):
        scores["pwn"] = scores.get("pwn", 0) + weight
        evidence.append(f"{source}ELF 信号且含远程服务线索 → pwn: {'、'.join(elf_hits)}")
    else:
        scores["reverse"] = scores.get("reverse", 0) + weight
        evidence.append(f"{source}ELF 信号（无远程服务线索）→ reverse: {'、'.join(elf_hits)}")
    if _PWN_BIAS_RE.search(lowered):
        scores["pwn"] = scores.get("pwn", 0) + _ELF_PWN_BIAS_WEIGHT
        evidence.append(f"{source}libc/ld 附件特征偏置 → pwn +{_ELF_PWN_BIAS_WEIGHT}")
    if _REVERSE_BIAS_RE.search(lowered):
        scores["reverse"] = scores.get("reverse", 0) + _ELF_REVERSE_BIAS_WEIGHT
        evidence.append(f"{source}加壳/注册类特征偏置 → reverse +{_ELF_REVERSE_BIAS_WEIGHT}")


def classify(
    target_spec: TargetSpec,
    goal: str,
    manifest: dict | None = None,
) -> CategoryDecision:
    """根据目标 + 用户任务目标执行初始题型分类。

    Args:
        target_spec: 结构化目标。
        goal: 用户的任务目标（必须使用真实 goal，不使用写死的默认值）。
        manifest: 可选的解压清单（用于文件类型信号匹配）。

    Returns:
        CategoryDecision，stage="initial"。
    """
    scores: dict[str, float] = {c: 0.0 for c in ALL_CATEGORIES}
    evidence: list[str] = []

    goal_lower = goal.lower()

    # ── 1. 关键词匹配（弱信号，短英文关键词按词边界） ──
    for cat, keywords in _KEYWORD_WEIGHTS.items():
        hits = 0
        for kw in keywords:
            if _keyword_matches(kw, goal_lower):
                hits += 1
        if hits > 0:
            scores[cat] += hits * 1.0
            evidence.append(f"goal 关键词命中 {cat}: {hits} 个")

    # ── 2. 文件名关键词（如果存在；同样按词边界）──
    if target_spec.original_path is not None:
        fname = target_spec.original_path.name.lower()
        for cat, keywords in _KEYWORD_WEIGHTS.items():
            if any(_keyword_matches(kw, fname) for kw in keywords):
                scores[cat] += _FILENAME_WEIGHT
                evidence.append(f"文件名命中 {cat}: {target_spec.original_path.name}")

    # ── 3. 目标类型基础分 ──
    defaults = _TARGET_KIND_DEFAULTS.get(target_spec.kind, ["unknown"])
    if "unknown" not in defaults and all(scores.get(c, 0) == 0 for c in ALL_CATEGORIES):
        for cat in defaults:
            if cat != "unknown":
                scores[cat] += 0.5
        evidence.append(f"目标类型默认: {target_spec.kind} → {defaults}")

    # ── 4. 文件内容/扩展名信号（如果有 manifest；强证据优先于题面弱关键词） ──
    if manifest:
        manifest_text = str(manifest).lower()
        for cat, signals in _FILE_TYPE_SIGNALS.items():
            for signal in signals:
                if signal.lower() in manifest_text:
                    scores[cat] += _FILE_SIGNAL_WEIGHT
                    evidence.append(f"文件信号命中 {cat}: {signal}")
                    break
        # ELF 证据条件归属（pwn 需远程服务线索，纯 ELF 归 reverse）
        elf_hits = [
            signal for signal in _ELF_FILE_TYPE_SIGNALS
            if signal.lower() in manifest_text
        ] + [
            ext for ext in _ELF_EXTENSIONS if ext in manifest_text
        ]
        _attribute_elf_signals(
            scores, evidence,
            elf_hits=elf_hits,
            context_text=f"{goal_lower} {manifest_text}",
            source="文件信号：",
        )
        # 扩展名强信号（独立于题面文本，文件类型证据优先）。
        # 例外：libc/ld 运行时附件的 .so 是 pwn 题提供物而非逆向对象，
        # 出现 libc 偏置特征时 .so 不再给 reverse 加分。
        libc_attachment = bool(_PWN_BIAS_RE.search(manifest_text))
        for cat, extensions in _EXTENSION_SIGNALS.items():
            for ext in extensions:
                if ext in manifest_text:
                    if ext == ".so" and libc_attachment:
                        evidence.append("扩展名 .so 为 libc 运行时附件，不计 reverse")
                        break
                    scores[cat] += _FILE_SIGNAL_WEIGHT
                    evidence.append(f"扩展名信号命中 {cat}: {ext}")
                    break

    # ── 5. 确定 primary ──
    if all(v == 0 for v in scores.values()):
        return CategoryDecision(
            primary="unknown",
            secondary=[],
            confidence=0.0,
            scores={},
            evidence=["无匹配信号，无法确定题型"],
            stage="initial",
        )

    # 按得分降序排序
    ranked = sorted(scores.items(), key=lambda x: (-x[1], x[0]))
    primary = ranked[0][0] if ranked[0][1] > 0 else "unknown"
    max_score = ranked[0][1] if ranked else 0
    total_score = sum(v for v in scores.values() if v > 0)

    # 置信度 = max_score / total_score（被归一化到 0-1）
    if total_score > 0:
        confidence = round(min(max_score / total_score, 1.0), 2)
    else:
        confidence = 0.0

    # secondary：得分 >= max_score * 0.6 的非 primary 题型
    secondary: list[CategoryName] = []
    for cat, sc in ranked[1:]:
        if sc >= max_score * 0.6 and sc > 1.0:
            secondary.append(cat)  # type: ignore[arg-type]

    # 得分太低的 unknown → 降低置信度
    if primary == "unknown" or max_score < 2.0:
        confidence = max(confidence - 0.3, 0.0)

    return CategoryDecision(
        primary=primary,
        secondary=secondary,
        confidence=confidence,
        scores={k: v for k, v in scores.items() if v > 0},
        evidence=evidence,
        stage="initial",
    )


def reclassify(
    previous: CategoryDecision,
    recon_evidence: list[str],
    new_signals: dict[str, float] | None = None,
) -> CategoryDecision:
    """基于侦察证据二次分类。

    Args:
        previous: 初始分类结果。
        recon_evidence: 侦察发现的证据文本列表。
        new_signals: 新增题型→得分映射（可选）。

    Returns:
        更新后的 CategoryDecision，stage="post_recon"。
    """
    scores = dict(previous.scores)
    evidence = list(previous.evidence)

    # 合并新信号
    if new_signals:
        for cat, sc in new_signals.items():
            scores[cat] = scores.get(cat, 0) + sc
            evidence.append(f"Recon 信号: {cat} +{sc}")

    # Recon 证据中的关键词弱匹配（短英文关键词按词边界）
    all_text = " ".join(recon_evidence).lower()
    for cat, keywords in _KEYWORD_WEIGHTS.items():
        hits = sum(1 for kw in keywords if _keyword_matches(kw, all_text))
        if hits > 0:
            scores[cat] = scores.get(cat, 0) + hits * 0.5
            if hits >= 2:
                evidence.append(f"Recon 关键词命中 {cat}: {hits} 个")

    # Recon 证据中的文件魔法强信号（ELF/PE/PCAP 等，优先于弱关键词）
    for cat, signals in _FILE_TYPE_SIGNALS.items():
        for signal in signals:
            if signal.lower() in all_text:
                scores[cat] = scores.get(cat, 0) + _FILE_SIGNAL_WEIGHT
                evidence.append(f"Recon 文件信号命中 {cat}: {signal}")
                break

    # ELF 证据条件归属（pwn 需远程服务线索，纯 ELF 归 reverse）
    elf_hits = [signal for signal in _ELF_FILE_TYPE_SIGNALS if signal.lower() in all_text]
    if elf_hits:
        _attribute_elf_signals(
            scores, evidence,
            elf_hits=elf_hits,
            context_text=f"{all_text} {' '.join(recon_evidence)}",
            source="Recon ",
        )

    # 重新排名
    if all(v == 0 for v in scores.values()):
        return CategoryDecision(
            primary="unknown",
            secondary=[],
            confidence=0.0,
            scores={},
            evidence=evidence,
            stage="post_recon",
        )

    ranked = sorted(scores.items(), key=lambda x: (-x[1], x[0]))
    primary = ranked[0][0] if ranked[0][1] > 0 else "unknown"
    max_score = ranked[0][1] if ranked else 0
    total_score = sum(v for v in scores.values() if v > 0)

    confidence = round(min(max_score / total_score, 1.0), 2) if total_score else 0.0

    secondary: list[CategoryName] = []
    for cat, sc in ranked[1:]:
        if sc >= max_score * 0.6 and sc > 1.0:
            secondary.append(cat)  # type: ignore[arg-type]

    return CategoryDecision(
        primary=primary,
        secondary=secondary,
        confidence=confidence,
        scores={k: v for k, v in scores.items() if v > 0},
        evidence=evidence,
        stage="post_recon",
    )


def extract_recon_signals(recon_evidence: list[str]) -> list[ReconSignal]:
    """从本轮 Recon 报告提取少量可验证强信号，不做开放式语义推断。"""
    text = "\n".join(str(item) for item in recon_evidence if str(item).strip())
    lowered = text.lower()
    signals: list[ReconSignal] = []
    seen: set[tuple[str, str]] = set()

    def add(category: CategoryName, content: str, score: float, confidence: float) -> None:
        key = (category, content)
        if key not in seen:
            seen.add(key)
            signals.append(ReconSignal(category, content, score, confidence))

    for category, patterns in _FILE_TYPE_SIGNALS.items():
        for pattern in patterns:
            if pattern.lower() in lowered:
                add(
                    category,  # type: ignore[arg-type]
                    f"Recon 工具输出确认文件类型信号：{pattern}",
                    float(_FILE_SIGNAL_WEIGHT),
                    0.95,
                )
                break

    # ELF 证据条件归属：报告同时出现 ELF 与远程服务连接线索 → pwn 强信号；
    # 纯 ELF（无远程）→ reverse 强信号。
    for pattern in _ELF_FILE_TYPE_SIGNALS:
        if pattern.lower() in lowered:
            has_remote = bool(_REMOTE_SERVICE_RE.search(lowered))
            owner: CategoryName = "pwn" if has_remote else "reverse"
            suffix = "且含远程服务连接线索" if has_remote else "（无远程服务线索）"
            add(
                owner,
                f"Recon 工具输出确认 ELF 文件{suffix}：{pattern}",
                float(_FILE_SIGNAL_WEIGHT),
                0.95,
            )
            break

    # HTTP 状态行、响应头和结构化侦察结论中的“协议: HTTP”都属于协议级
    # 证据，比题面中的普通“web/http”关键词可靠。报告通常会把 curl 原始
    # 响应压缩成 Markdown 表格，不能只依赖 ``HTTP/1.1 200`` 这一种写法。
    http_match = re.search(r"\bHTTP/[12](?:\.\d)?\s+\d{3}\b", text, re.IGNORECASE)
    header_match = re.search(r"\b(?:server|content-type):\s*[^\r\n]+", text, re.IGNORECASE)
    protocol_field_match = re.search(
        r"(?:^|\n)[^\n]*(?:协议|protocol)[^\n]{0,100}\bhttps?\b",
        text,
        re.IGNORECASE,
    )
    if http_match or header_match or protocol_field_match:
        value = (
            http_match.group(0) if http_match else
            "HTTP 响应头" if header_match else
            "结构化侦察结论中的 HTTP 协议"
        )
        add("web", f"Recon 工具输出确认 Web 协议响应：{value}", 8.0, 0.9)

    # 密码材料和抓包/内存格式补充信号；仅匹配明确格式名，不把泛化词当事实。
    for token in ("RSA PUBLIC KEY", "BEGIN PUBLIC KEY", "BEGIN RSA PRIVATE KEY"):
        if token.lower() in lowered:
            add("crypto", f"Recon 工具输出确认密码材料：{token}", 8.0, 0.9)
            break
    for token in ("pcapng", "tcpdump capture file", "crash dump", "memory dump"):
        if token in lowered:
            add("forensics", f"Recon 工具输出确认取证格式：{token}", 10.0, 0.95)
            break
    return signals


def evaluate_reclassification(
    previous: CategoryDecision,
    recon_evidence: list[str],
    *,
    seen_evidence_fingerprints: set[str] | None = None,
) -> ReclassificationResult:
    """对一批全新 Recon 证据执行一次可审计的分类接受判定。

    初始分类是已知题型时，新题型必须至少领先旧题型 5 分；初始 unknown
    则只需出现置信度不低于 0.55 的明确新类别。相同证据批不会重复计分。
    """
    normalized = "\n".join(str(item).strip() for item in recon_evidence if str(item).strip())
    fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if seen_evidence_fingerprints and fingerprint in seen_evidence_fingerprints:
        return ReclassificationResult(
            candidate=previous,
            accepted=False,
            reason="本批 Recon 证据已评估，拒绝重复计分",
            evidence_fingerprint=fingerprint,
        )

    signals = extract_recon_signals(recon_evidence)
    structured_scores: dict[str, float] = {}
    for signal in signals:
        structured_scores[signal.category] = (
            structured_scores.get(signal.category, 0.0) + signal.score
        )
    candidate = reclassify(previous, recon_evidence, structured_scores)

    if candidate.primary == previous.primary:
        return ReclassificationResult(
            candidate=candidate,
            accepted=False,
            reason="新增证据未改变主题型",
            signals=signals,
            evidence_fingerprint=fingerprint,
        )
    candidate_score = float(candidate.scores.get(candidate.primary, 0.0))
    previous_score = float(candidate.scores.get(previous.primary, 0.0))
    strong_new_signal = any(
        signal.category == candidate.primary and signal.confidence >= 0.9
        for signal in signals
    )
    if previous.primary == "unknown":
        accepted = candidate.primary != "unknown" and (
            candidate.confidence >= 0.55 or strong_new_signal
        )
    else:
        # pwn 与 reverse 共享 ELF 特征、易互混，翻盘领先门槛放宽为 3 分。
        lead = 3.0 if {previous.primary, candidate.primary} == {"pwn", "reverse"} else 5.0
        accepted = (
            candidate.confidence >= 0.55
            and candidate_score >= previous_score + lead
            and strong_new_signal
        )
    reason = (
        f"接受新分类 {previous.primary} → {candidate.primary}："
        f"confidence={candidate.confidence:.2f}, score={candidate_score:.1f}"
        if accepted else
        f"拒绝分类变化 {previous.primary} → {candidate.primary}："
        "新分类未同时满足置信度、领先分差和强证据要求"
    )
    return ReclassificationResult(
        candidate=candidate,
        accepted=accepted,
        reason=reason,
        signals=signals,
        evidence_fingerprint=fingerprint,
    )
