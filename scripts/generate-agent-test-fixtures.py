#!/usr/bin/env python3
"""生成灵枢本地功能测试附件。

所有内容均为合成数据；脚本不会联网、扫描主机或执行生成的样本。
默认输出到 ``WorkDir/test-fixtures``，可直接上传到 Web 控制台测试附件路由。
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import textwrap
import zipfile
from pathlib import Path


def write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def build_fixture(root: Path, *, force: bool = False) -> None:
    if root.exists() and any(root.iterdir()) and not force:
        raise SystemExit(f"输出目录非空：{root}；如需覆盖请显式传入 --force")
    if root.exists() and force:
        for child in root.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    root.mkdir(parents=True, exist_ok=True)

    write(root / "taskbook-pentest.md", """
        # 合成授权测试任务书

        - 任务类型：授权安全测试任务书
        - 目标地址：127.0.0.1
        - 服务端口：8080
        - 测试范围：仅限本机模拟服务，不得访问其他地址
        - 要求：先进行本地附件分析，再由 Orchestrator 决定是否进行被动网络侦察
    """)
    write(root / "incident-response.log", """
        2026-08-25T10:00:01Z host=ir-lab-01 event=login user=test source=127.0.0.1
        2026-08-25T10:00:03Z process=/usr/bin/example status=quarantined
        2026-08-25T10:00:05Z finding=synthetic-suspicious-string severity=medium
    """)
    write(root / "reverse-hints.txt", """
        SYNTHETIC_REVERSE_FIXTURE
        candidate_flag=CTF{local_fixture_only}
        function=verify_candidate
        string=not_a_real_secret
    """)
    write(root / "network-observations.json", json.dumps({
        "fixture": True,
        "authorized_target": "127.0.0.1",
        "port": 8080,
        "note": "Synthetic data; do not treat as a live service.",
    }, ensure_ascii=False, indent=2) + "\n")

    source = root / "sample.c"
    write(source, """
        #include <stdio.h>
        int main(void) {
            puts("SYNTHETIC_ELF_FIXTURE");
            puts("CTF{local_fixture_only}");
            return 0;
        }
    """)
    gcc = shutil.which("gcc")
    if gcc:
        result = subprocess.run(
            [gcc, "-O0", "-g", str(source), "-o", str(root / "sample-elf")],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode != 0:
            write(root / "sample-elf.build-error.txt", result.stderr)
    else:
        write(root / "sample-elf.build-error.txt", "gcc unavailable; use sample.c for static-analysis tests.\n")

    archive = root / "ctf-pwn-fixture.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(root.iterdir()):
            if path.name == archive.name or path.is_dir():
                continue
            bundle.write(path, arcname=path.name)

    write(root / "README.md", """
        # Fixture 使用建议

        1. SM-02：上传 `incident-response.log` 或 `reverse-hints.txt`。
        2. SM-03 / NR-02：上传 `ctf-pwn-fixture.zip`，授权目标填写 `127.0.0.1`，任务目标注明“CTF PWN”。
        3. AT-02：上传 `taskbook-pentest.md`，授权目标填写 `127.0.0.1`。
        4. RV-01：上传 `sample-elf`；若本机没有 gcc，则上传 `sample.c`。

        所有目标均为文档中的合成地址，不代表真实服务，不应替换为未授权目标。
    """)


def main() -> None:
    parser = argparse.ArgumentParser(description="生成灵枢合成功能测试附件")
    parser.add_argument("--output", type=Path, default=Path("WorkDir/test-fixtures"))
    parser.add_argument("--force", action="store_true", help="覆盖已有输出目录内容")
    args = parser.parse_args()
    build_fixture(args.output.resolve(), force=args.force)
    print(f"已生成测试附件：{args.output.resolve()}")


if __name__ == "__main__":
    main()
