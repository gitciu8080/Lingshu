#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
session_stats.py — 灵枢 Agent 会话数据统计脚本

数据源:
  1. PostgreSQL（sessions / session_messages / users 表, 权威数据）
  2. .TaskMemory/sessions/*.json  （任务状态快照, 含 category_decision 题型判定）

输出:
  1. 控制台摘要
  2. Markdown 报告 → .Reports/session_statistics.md

用法:
  python3 scripts/session_stats.py
"""
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.database import get_db

SNAPSHOT_DIR = os.path.join(ROOT, ".TaskMemory", "sessions")
OUT_PATH = os.path.join(ROOT, "docs", "session_statistics.md")

CST = timezone(timedelta(hours=8))


UTC8 = timezone(timedelta(hours=8))


def parse_ts(s: str, is_updated: bool = False) -> datetime | None:
    """解析时间戳为 UTC datetime。

    兼容历史数据的 naive 时间与 PostgreSQL 返回的带时区时间。
    """
    if not s:
        return None
    s = str(s).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            if is_updated:
                dt = dt.replace(tzinfo=UTC8)
            else:
                dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def classify_target(t: str) -> str:
    """按 target 字段分类目标类型。"""
    t = (t or "").strip()
    if not t:
        return "empty"
    has_local = "/" in t and ("uploads" in t or t.startswith("/") or t.startswith("WorkDir"))
    has_net = bool(
        re.search(r"(https?://|[a-z0-9.-]+\.(cn|com|org|net)|remote\s*\(|^nc\s)", t, re.I)
    )
    if t.startswith(("http://", "https://")):
        return "web_url"
    if has_local and has_net:
        return "mixed(网络+本地)"
    if has_local:
        return "local_file"
    if t.startswith(("nc ", "remote(")):
        return "network"
    if re.match(r"^[\w.-]+(:\d+)?$", t):
        return "network"
    return "other"


def main():
    conn = get_db()
    cur = conn.cursor()

    # ── 1. 会话基本数据 ──────────────────────────────────────────────
    sessions = [dict(r) for r in cur.execute("SELECT * FROM sessions")]
    users = {r["id"]: r["username"] for r in cur.execute("SELECT id, username, role FROM users")}
    total = len(sessions)

    # ── 2. TaskMemory 快照: session_id → 题型判定 ─────────────────────
    category_map = {}      # session_id -> primary 题型
    approval_detail = {}   # session_id -> 审批结果列表
    action_counter = Counter()   # 快照事件 action 统计
    snap_ok = 0
    for fn in os.listdir(SNAPSHOT_DIR):
        try:
            with open(os.path.join(SNAPSHOT_DIR, fn), encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        sid = d.get("session_id") or os.path.splitext(fn)[0]
        snap_ok += 1
        cd = d.get("category_decision") or {}
        category_map[sid] = cd.get("primary") or "unknown"
        # 审批事件详情 + 动作统计
        for e in d.get("events", []):
            act = e.get("action")
            action_counter[act] += 1
            if act == "exploitation_approval":
                det = e.get("details") or {}
                approval_detail.setdefault(sid, []).append(det)

    # ── 3. 消息流统计 ────────────────────────────────────────────────
    tool_calls_total = 0
    tool_by_name = Counter()
    tool_by_agent = Counter()
    tool_by_phase = Counter()
    tool_by_session = Counter()
    tool_end_by_session = Counter()
    tool_fail_by_session = Counter()  # start 无配对 end
    evt_counts = Counter()
    phase_by_session = Counter()
    msg_by_session = Counter()
    nss_correct = 0
    nss_wrong = 0
    approval_req_by_session = set()
    approval_res_by_session = set()

    for r in cur.execute(
        "SELECT session_id, seq, role, content, event_type, agent_name "
        "FROM session_messages ORDER BY session_id, seq"
    ):
        sid, et = r["session_id"], r["event_type"]
        evt_counts[et] += 1
        msg_by_session[sid] += 1
        if et == "phase_change" and isinstance(r["content"], str):
            phase_by_session[sid] = r["content"].strip()
        if et == "tool_call_start":
            tool_calls_total += 1
            raw = (r["content"] or "").strip()
            name = raw
            # 部分记录 content 为 JSON 字符串(含 tool_call_id/tool_name)
            if name.startswith("{"):
                try:
                    name = (json.loads(name).get("tool_name") or "").strip()
                except Exception:
                    name = ""
            if not name:
                name = "(unknown/脱敏)"
            tool_by_name[name] += 1
            tool_by_agent[r["agent_name"] or "(none)"] += 1
            tool_by_phase[phase_by_session.get(sid, "planning")] += 1
            tool_by_session[sid] += 1
        elif et == "tool_call_end":
            tool_end_by_session[sid] += 1
        elif et == "approval_required":
            approval_req_by_session.add(sid)
        elif et == "approval_resolved":
            approval_res_by_session.add(sid)
        elif et == "nss_submit" and isinstance(r["content"], str):
            try:
                payload = json.loads(r["content"])
                if payload.get("correct"):
                    nss_correct += 1
                else:
                    nss_wrong += 1
            except Exception:
                pass

    # 工具调用失败(未配对 end)的会话级统计
    for sid, n in tool_by_session.items():
        tool_fail_by_session[sid] = max(0, n - tool_end_by_session.get(sid, 0))
    failed_tool_calls = sum(tool_fail_by_session.values())

    # ── 4. 会话级派生统计 ────────────────────────────────────────────
    def ok_count(rows):
        return sum(1 for r in rows if r["success"] == 1)

    def fail_count(rows):
        return sum(1 for r in rows if r["success"] == 0)

    def none_count(rows):
        return sum(1 for r in rows if r["success"] is None)

    def rate(done, total_):
        return f"{done / total_ * 100:.1f}%" if total_ else "-"

    status_c = Counter(r["status"] for r in sessions)
    phase_c = Counter(r["phase"] for r in sessions)
    model_c = Counter((r["provider"] or "?" , r["model"] or "?") for r in sessions)
    user_c = Counter(users.get(r["user_id"], f"u{r['user_id']}") for r in sessions)
    target_type_c = Counter(classify_target(r["target"]) for r in sessions)
    cat_c = Counter(category_map.get(r["id"], "unknown") for r in sessions)
    flag_c = sum(1 for r in sessions if r["flag"])
    summary_nonempty = sum(1 for r in sessions if r["summary"])

    # 时长（全部 / 已终结 completed+failed）；负值(时区写入不一致)剔除
    durations = []
    durations_terminal = []
    duration_skipped = 0
    for r in sessions:
        t0, t1 = parse_ts(r["created_at"]), parse_ts(r["updated_at"], is_updated=True)
        if t0 and t1:
            delta = (t1 - t0).total_seconds()
            if delta < 0:
                duration_skipped += 1
                continue
            durations.append(delta)
            if r["status"] in ("completed", "failed"):
                durations_terminal.append(delta)
    def dur_stats(arr):
        if not arr:
            return "-"
        return (f"均值 {statistics.mean(arr)/60:.1f} 分钟, "
                f"中位 {statistics.median(arr)/60:.1f} 分钟, "
                f"范围 {min(arr)/60:.1f}~{max(arr)/60:.1f} 分钟")

    # 按天分布
    day_c = Counter()
    for r in sessions:
        dt = parse_ts(r["created_at"])
        if dt:
            day_c[dt.astimezone(CST).strftime("%m-%d")] += 1

    # ── 5. 分类型成功率 ──────────────────────────────────────────────
    def success_by(keyfn, filter_=None):
        buckets = defaultdict(list)
        for r in sessions:
            if filter_ and not filter_(r):
                continue
            buckets[keyfn(r)].append(r)
        rows = []
        for k, rs in sorted(buckets.items(), key=lambda kv: -sum(1 for x in kv[1] if x["success"] == 1)):
            done = ok_count(rs) + fail_count(rs)
            rows.append((k, len(rs), ok_count(rs), fail_count(rs), none_count(rs),
                         rate(ok_count(rs), done), rate(ok_count(rs), len(rs))))
        return rows

    # 题型（category_decision.primary）
    by_cat = success_by(lambda r: category_map.get(r["id"], "unknown"))
    # 目标类型
    by_target = success_by(lambda r: classify_target(r["target"]))
    # 模型
    by_model = success_by(lambda r: f"{r['provider']}/{r['model']}")
    # 用户
    by_user = success_by(lambda r: users.get(r["user_id"], f"u{r['user_id']}"))
    # title 大类（如 Web 安全 / 二进制利用 / AI 安全 ...）
    def title_cat(r):
        t = r["title"] or ""
        m = re.match(r"^\[[^\]]+\]\s*([^\s·-]+)", t)
        if m:
            return m.group(1)
        return "(未标注)"
    by_title = success_by(title_cat)

    # 会话涉及的 user_id 数
    sess_user_ids = {r["user_id"] for r in sessions}

    # ── 6. 审批统计 ──────────────────────────────────────────────────
    approved_sessions = 0
    rejected_sessions = 0
    approved_events = 0
    rejected_events = 0
    for sid, details in approval_detail.items():
        per_sid = []
        for d in details:
            ap = d.get("approved")
            if ap is True:
                approved_events += 1
                per_sid.append(True)
            elif ap is False:
                rejected_events += 1
                per_sid.append(False)
        last = per_sid[-1] if per_sid else None
        if last is True:
            approved_sessions += 1
        elif last is False:
            rejected_sessions += 1
    snap_explo = 0
    for fn in os.listdir(SNAPSHOT_DIR):
        try:
            with open(os.path.join(SNAPSHOT_DIR, fn), encoding="utf-8") as f:
                d = json.load(f)
            if d.get("exploitation_approved"):
                snap_explo += 1
        except Exception:
            pass

    # 成功会话的 flag 覆盖率
    ok_sessions = [r for r in sessions if r["success"] == 1]
    ok_with_flag = sum(1 for r in ok_sessions if r["flag"])

    # ── 输出 ─────────────────────────────────────────────────────────
    L = []
    w = L.append
    w("# 灵枢 Agent 会话数据统计报告")
    w("")
    w(f"> 生成时间: {datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)")
    w(f"> 数据源: PostgreSQL + `.TaskMemory/sessions/` (任务快照, 读取 {snap_ok} 个)")
    w("")
    w("## 一、总体概览")
    w("")
    w("| 指标 | 值 |")
    w("|---|---|")
    w(f"| 会话总数 | {total} |")
    w(f"| 用户数 | {len(users)} (会话涉及 {len(sess_user_ids)} 个 user_id, 其中 "
      f"{len(sess_user_ids) - len(set(users) & sess_user_ids)} 个已无对应用户记录) |")
    w(f"| 时间范围 | {min((parse_ts(r['created_at']) for r in sessions if parse_ts(r['created_at'])), default='-').astimezone(CST):%Y-%m-%d} ~ {max((parse_ts(r['created_at']) for r in sessions if parse_ts(r['created_at'])), default='-').astimezone(CST):%Y-%m-%d} |")
    w(f"| 消息总数 | {sum(msg_by_session.values())} |")
    w(f"| 工具调用总数 (tool_call_start) | {tool_calls_total} |")
    w(f"| 工具调用未正常结束数 | {failed_tool_calls} |")
    w(f"| 会话平均消息数 | {statistics.mean(msg_by_session.values()):.0f} (中位 {statistics.median(msg_by_session.values()):.0f}) |")
    w(f"| 会话平均工具调用数 | {tool_calls_total/total:.1f} (中位 {statistics.median(list(tool_by_session.values())):.0f}) |")
    w(f"| 会话平均时长 (全部) | {dur_stats(durations)} |")
    w(f"| 会话平均时长 (仅已终结) | {dur_stats(durations_terminal)} |")
    if duration_skipped:
        w(f"| 时长剔除 (负值/时区不一致) | {duration_skipped} |")
    w(f"| 成功会话带 flag 比例 | {ok_with_flag}/{ok_count(sessions)} ({rate(ok_with_flag, ok_count(sessions))}) |")
    w("")
    w("## 二、状态与阶段分布")
    w("")
    w("### 2.1 会话状态")
    w("")
    w("| 状态 | 数量 | 占比 |")
    w("|---|---|---|")
    for k, v in status_c.most_common():
        w(f"| {k} | {v} | {v/total*100:.1f}% |")
    w("")
    w("### 2.2 最终阶段 (phase)")
    w("")
    w("| 阶段 | 数量 | 占比 |")
    w("|---|---|---|")
    for k, v in phase_c.most_common():
        w(f"| {k} | {v} | {v/total*100:.1f}% |")
    w("")
    w("## 三、成功率")
    w("")
    w("### 3.1 整体成功率")
    w("")
    ok_, fail_, none_ = ok_count(sessions), fail_count(sessions), none_count(sessions)
    w("| 口径 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |")
    w("|---|---|---|---|---|---|")
    w(f"| 全部会话 | {ok_} | {fail_} | {none_} | {rate(ok_, ok_+fail_)} | {rate(ok_, total)} |")
    w("")
    w("> 已终结 = success 有明确值 (0/1)；无结果 = success 为 NULL (含 active / cancelled / 异常中断)。")
    w("")
    w("### 3.2 按题型 (category_decision.primary) 分任务类型成功率")
    w("")
    w("| 题型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |")
    w("|---|---|---|---|---|---|---|")
    for k, n, a, b, c, r1, r2 in by_cat:
        w(f"| {k} | {n} | {a} | {b} | {c} | {r1} | {r2} |")
    w("")
    w("### 3.3 按目标类型成功率")
    w("")
    w("| 目标类型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |")
    w("|---|---|---|---|---|---|---|")
    for k, n, a, b, c, r1, r2 in by_target:
        w(f"| {k} | {n} | {a} | {b} | {c} | {r1} | {r2} |")
    w("")
    w("### 3.4 按模型 (provider/model) 成功率")
    w("")
    w("| 模型 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |")
    w("|---|---|---|---|---|---|---|")
    for k, n, a, b, c, r1, r2 in by_model:
        w(f"| {k} | {n} | {a} | {b} | {c} | {r1} | {r2} |")
    w("")
    w("### 3.5 按用户成功率")
    w("")
    w("| 用户 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |")
    w("|---|---|---|---|---|---|---|")
    for k, n, a, b, c, r1, r2 in by_user:
        w(f"| {k} | {n} | {a} | {b} | {c} | {r1} | {r2} |")
    w("")
    w("### 3.6 按任务大类 (title 前缀) 成功率")
    w("")
    w("| 任务大类 | 会话数 | 成功 | 失败 | 无结果 | 成功率(已终结) | 成功率(全部) |")
    w("|---|---|---|---|---|---|---|")
    for k, n, a, b, c, r1, r2 in by_title:
        w(f"| {k} | {n} | {a} | {b} | {c} | {r1} | {r2} |")
    w("")
    w("## 四、会话类型分布")
    w("")
    w("### 4.1 题型判定分布 (category_decision.primary)")
    w("")
    w("| 题型 | 会话数 | 占比 |")
    w("|---|---|---|")
    for k, v in cat_c.most_common():
        w(f"| {k} | {v} | {v/total*100:.1f}% |")
    w("")
    w("### 4.2 目标类型分布")
    w("")
    w("| 目标类型 | 会话数 | 占比 |")
    w("|---|---|---|")
    for k, v in target_type_c.most_common():
        w(f"| {k} | {v} | {v/total*100:.1f}% |")
    w("")
    w("### 4.3 模型分布")
    w("")
    w("| Provider/Model | 会话数 | 占比 |")
    w("|---|---|---|")
    for (p, m), v in model_c.most_common():
        w(f"| {p}/{m} | {v} | {v/total*100:.1f}% |")
    w("")
    w("### 4.4 用户分布")
    w("")
    w("| 用户 | 会话数 | 占比 |")
    w("|---|---|---|")
    for k, v in user_c.most_common():
        w(f"| {k} | {v} | {v/total*100:.1f}% |")
    w("")
    w("### 4.5 每日会话创建量 (UTC+8)")
    w("")
    w("| 日期 | 会话数 |")
    w("|---|---|")
    for k in sorted(day_c):
        bar = "█" * round(day_c[k] / max(day_c.values()) * 30)
        w(f"| {k} | {day_c[k]} `{bar}` |")
    w("")
    # 每会话工具调用分布分位数
    per_sess = sorted(tool_by_session.values())
    def pct(p):
        if not per_sess:
            return 0
        idx = min(len(per_sess) - 1, int(len(per_sess) * p))
        return per_sess[idx]

    # 可识别工具名占比（排除脱敏占位）
    named_tools = sum(v for k, v in tool_by_name.items() if k != "(unknown/脱敏)")

    w("## 五、工具调用统计")
    w("")
    w("### 5.1 总量")
    w("")
    w("| 指标 | 值 |")
    w("|---|---|")
    w(f"| tool_call_start 事件 | {tool_calls_total} |")
    w(f"| tool_call_end 事件 | {sum(tool_end_by_session.values())} |")
    w(f"| 未配对 (start 无 end, 异常中断) | {failed_tool_calls} |")
    w(f"| 每会话平均 | {tool_calls_total/total:.1f} 次 |")
    w(f"| 每会话中位数 | {statistics.median(per_sess):.0f} 次 |")
    w(f"| 每会话分位 (P25/P75/P90) | {pct(0.25)}/{pct(0.75)}/{pct(0.9)} 次 |")
    w(f"| 单会话最多 | {max(per_sess)} 次 |")
    w("")
    w("> 注意：历史记录中大部分 `tool_call_start` 的工具名曾因脱敏缺失（content 为空），"
      f"当前数据源经回填后可识别 {named_tools}/{tool_calls_total} 次"
      f"（{named_tools/tool_calls_total*100:.1f}%）。"
      " 5.2 节基于可识别子集统计；另 `update_plan` 与 `UpdatePlan` 为历史版本命名不一致的同一工具。")
    w("")
    w("### 5.2 可识别工具名分布 (Top 30, 占全部调用的 "
      f"{named_tools/tool_calls_total*100:.1f}%)")
    w("")
    w("| 工具 | 调用次数 | 占可识别比例 |")
    w("|---|---|---|")
    for name, v in tool_by_name.most_common(30):
        w(f"| `{name}` | {v} | {v/named_tools*100:.1f}% |")
    w("")
    w("### 5.3 按 Agent 角色")
    w("")
    w("| Agent | 工具调用 | 全部消息 |")
    w("|---|---|---|")
    all_msg_by_agent = Counter()
    for r in cur.execute("SELECT agent_name FROM session_messages"):
        all_msg_by_agent[r[0] or "(none)"] += 1
    for k, v in tool_by_agent.most_common(25):
        w(f"| {k} | {v} | {all_msg_by_agent.get(k, 0)} |")
    w("")
    w("### 5.4 按任务阶段")
    w("")
    w("| 阶段 | 工具调用 | 占比 |")
    w("|---|---|---|")
    for k, v in tool_by_phase.most_common():
        w(f"| {k} | {v} | {v/tool_calls_total*100:.1f}% |")
    w("")
    w("## 六、人工审批")
    w("")
    w("| 指标 | 值 |")
    w("|---|---|")
    w(f"| 请求过利用审批的会话数 | {len(approval_req_by_session)} |")
    w(f"| approval_required 事件总数 | {evt_counts['approval_required']} |")
    w(f"| approval_resolved 事件总数 | {evt_counts['approval_resolved']} |")
    w(f"| 快照中 exploitation_approval 事件 | {action_counter.get('exploitation_approval', 0)} |")
    w(f"| 审批通过 (事件级) | {approved_events} ({approved_events/(approved_events+rejected_events)*100:.1f}%) |")
    w(f"| 审批拒绝 (事件级) | {rejected_events} ({rejected_events/(approved_events+rejected_events)*100:.1f}%) |")
    w(f"| 至少一次批准的会话 | {approved_sessions} |")
    w(f"| 最终被拒绝的会话 | {rejected_sessions} |")
    w(f"| 快照中 exploitation_approved=true 的会话 | {snap_explo} |")
    w("")
    w("## 七、Flag 与提交")
    w("")
    w("| 指标 | 值 |")
    w("|---|---|")
    w(f"| flag_found 事件 | {evt_counts['flag_found']} |")
    w(f"| 会话表含 flag 的会话 | {flag_c} |")
    w(f"| nss_submit 事件 | {evt_counts['nss_submit']} (正确 {nss_correct}, 错误 {nss_wrong}) |")
    w(f"| report_ready 事件 | {evt_counts['report_ready']} |")
    w(f"| 会话表 summary 非空 | {summary_nonempty} |")
    w("")
    w("## 八、其他事件统计 (session_messages.event_type)")
    w("")
    w("| 事件类型 | 数量 |")
    w("|---|---|")
    for k, v in evt_counts.most_common():
        w(f"| {k} | {v} |")
    w("")
    w("## 九、错误与异常")
    w("")
    err_by_sid = Counter()
    for r in cur.execute("SELECT session_id FROM session_messages WHERE event_type='error'"):
        err_by_sid[r["session_id"]] += 1
    w(f"| 含 error 事件的会话数 | {len(err_by_sid)} |")
    w(f"| error 事件总数 | {evt_counts['error']} |")
    w("")
    w("## 十、系统级动作统计 (TaskMemory 事件链)")
    w("")
    w("| 动作 | 次数 |")
    w("|---|---|")
    for k, v in action_counter.most_common():
        w(f"| {k} | {v} |")
    w("")
    w("---")
    w("*本报告由 `scripts/session_stats.py` 自动生成。*")

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    # ── CSV 明细导出（会话级）───────────────────────────────────────
    import csv
    csv_path = os.path.join(ROOT, "docs", "session_stats.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "session_id", "user", "provider", "model", "target", "target_type",
            "goal", "category", "title", "status", "phase", "success",
            "flag", "tool_calls", "messages", "duration_min",
            "created_at", "updated_at",
        ])
        for r in sessions:
            t0, t1 = parse_ts(r["created_at"]), parse_ts(r["updated_at"], is_updated=True)
            dur = ""
            if t0 and t1 and (t1 - t0).total_seconds() >= 0:
                dur = round((t1 - t0).total_seconds() / 60, 1)
            writer.writerow([
                r["id"], users.get(r["user_id"], f"u{r['user_id']}"),
                r["provider"], r["model"], r["target"],
                classify_target(r["target"]), (r["goal"] or "")[:100],
                category_map.get(r["id"], "unknown"), r["title"] or "",
                r["status"], r["phase"], r["success"], r["flag"] or "",
                tool_by_session.get(r["id"], 0), msg_by_session.get(r["id"], 0),
                dur, r["created_at"], r["updated_at"],
            ])
    print(f"CSV 明细已写入: {csv_path}")
    print(f"报告已写入: {OUT_PATH}")
    print("\n".join(L[:60]))
    conn.close()


if __name__ == "__main__":
    main()
