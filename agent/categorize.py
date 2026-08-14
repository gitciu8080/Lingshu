"""评分制题型分类模块。

关键词作为弱证据（每命中 +1 分），文件内容信号权重更高（+5~+15 分）。
分类只产生一次正式结果写入 MissionState，Attack 不自行重新分类。
支持初始分类（initial）和后侦察二次分类（post_recon）。
"""
from __future__ import annotations

import re
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
_FILE_TYPE_SIGNALS: dict[str, list[str]] = {
    "pwn": ["ELF", "executable, x86", "LSB executable", "ELF 64-bit"],
    "reverse": ["Mach-O", "PE32", "DEX", "Java class", "WASM", "APK"],
    "forensics": ["pcap", "pcapng", "tcpdump", "PCAP", "PCAPNG"],
    "malware": ["PE32+", "Microsoft executable"],
    "misc": ["Python script", "ASCII text"],
}

# 文件类型信号权重
_FILE_SIGNAL_WEIGHT = 10

# 扩展名强信号：独立于题面文本，文件类型证据优先于弱关键词
_EXTENSION_SIGNALS: dict[str, list[str]] = {
    "pwn": [".elf"],
    "reverse": [".exe", ".dll", ".apk", ".dex", ".class", ".wasm", ".so", ".ko"],
    "forensics": [".pcap", ".pcapng", ".raw", ".img", ".dd", ".mem", ".vmem"],
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


# ---------------------------------------------------------------------------
# 分类函数
# ---------------------------------------------------------------------------


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
        # 扩展名强信号（独立于题面文本，文件类型证据优先）
        for cat, extensions in _EXTENSION_SIGNALS.items():
            for ext in extensions:
                if ext in manifest_text:
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
