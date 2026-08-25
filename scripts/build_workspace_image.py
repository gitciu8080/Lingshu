#!/usr/bin/env python3
"""Pre-build the DockerWorkspace derived image used by AgentScope."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_BASE_IMAGE = "kali-full:latest"
DEFAULT_EXTRA_PIP_ENV = "LINGSHU_WORKSPACE_DOCKER_EXTRA_PIP"
BASE_IMAGE_ENV = "LINGSHU_WORKSPACE_BASE_IMAGE"


def load_dotenv(path: Path) -> None:
    """Load simple KEY=VALUE entries without requiring python-dotenv."""
    if not path.is_file():
        return

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pre-build the AgentScope DockerWorkspace derived image.",
    )
    parser.add_argument(
        "base_image",
        nargs="?",
        help=f"Base image (default: {BASE_IMAGE_ENV} or {DEFAULT_BASE_IMAGE})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate and display the build context without building.",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Display the generated Dockerfile after generation/build.",
    )
    return parser.parse_args()


def find_python_command() -> list[str]:
    preferred = Path("/home/gitciu/miniconda3/envs/agentscope/bin/python")
    if preferred.is_file() and os.access(preferred, os.X_OK):
        return [str(preferred)]

    conda = shutil.which("conda")
    if conda:
        return [conda, "run", "-n", "agentscope", "python"]

    python3 = shutil.which("python3")
    if python3:
        return [python3]

    if sys.executable:
        return [sys.executable]

    raise RuntimeError(
        "找不到 Python 解释器；请先安装包含 agentscope 的 Python 环境。",
    )


def generate_build_context(
    python_command: list[str],
    base_image: str,
    extra_pip: list[str],
    output_dir: Path,
) -> str:
    code = r"""
import json
import sys
from pathlib import Path
from agentscope.workspace._docker._make_dockerfile import prepare_build_context

base_image = sys.argv[1]
outdir = Path(sys.argv[2])
extra_pip = json.loads(sys.argv[3])

outdir.mkdir(parents=True, exist_ok=True)
ctx, tag, files = prepare_build_context(
    base_image=base_image,
    extra_pip=extra_pip,
)
(outdir / "Dockerfile").write_bytes((ctx / "Dockerfile").read_bytes())
for name in ("requirements.txt", "_mcp_gateway_app.py", "_glob_helper.py"):
    (outdir / name).write_bytes(files[name])
(outdir / "TAG").write_text(tag, encoding="utf-8")
"""
    result = subprocess.run(
        [
            *python_command,
            "-c",
            code,
            base_image,
            str(output_dir),
            json.dumps(extra_pip),
        ],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"生成 AgentScope Docker 构建上下文失败，退出码：{result.returncode}",
        )

    tag_file = output_dir / "TAG"
    if not tag_file.is_file():
        raise RuntimeError("AgentScope 未返回派生镜像 tag。")
    return tag_file.read_text(encoding="utf-8").strip()


def run_command(command: list[str]) -> None:
    print("[INFO]", shlex.join(command))
    subprocess.run(command, check=True)


def docker_command(command: list[str]) -> list[str]:
    """Use the docker group helper on Linux when it is available."""
    if os.name != "nt" and shutil.which("sg"):
        return ["sg", "docker", "-c", shlex.join(command)]
    return command


def image_exists(tag: str) -> bool:
    result = subprocess.run(
        docker_command(["docker", "image", "inspect", tag]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def main() -> int:
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    project_dir = script_dir.parent
    load_dotenv(project_dir / ".env")

    base_image = args.base_image or os.getenv(BASE_IMAGE_ENV, DEFAULT_BASE_IMAGE)
    extra_pip = [
        item.strip()
        for item in os.getenv(DEFAULT_EXTRA_PIP_ENV, "").split(",")
        if item.strip()
    ]
    python_command = find_python_command()

    with tempfile.TemporaryDirectory(prefix="lingshu-workspace-") as temp_dir:
        build_dir = Path(temp_dir)
        print(f"[INFO] 生成构建上下文（base={base_image}）...")
        print(f"[INFO] 使用 Python：{shlex.join(python_command)}")
        if extra_pip:
            print(f"[INFO] 额外 pip 包：{', '.join(extra_pip)}")

        tag = generate_build_context(
            python_command,
            base_image,
            extra_pip,
            build_dir,
        )
        dockerfile = build_dir / "Dockerfile"
        print(f"[INFO] 派生镜像 tag：{tag}")

        if args.dry_run:
            print("\n========== DRY RUN ==========")
            print(f"基础镜像：{base_image}")
            print(f"镜像 tag：{tag}")
            if extra_pip:
                print(f"额外 pip：{', '.join(extra_pip)}")
            print(f"构建上下文：{build_dir}")
            print("Dockerfile:")
            print("-" * 30)
            print(dockerfile.read_text(encoding="utf-8"))
            print("-" * 30)
            print(
                "命令：",
                shlex.join(
                    [
                        "docker",
                        "build",
                        "--network",
                        "host",
                        "-t",
                        tag,
                        "-f",
                        str(dockerfile),
                        str(build_dir),
                    ],
                ),
            )
            print("==============================")
            return 0

        if image_exists(tag):
            print(f"[INFO] 镜像已存在，跳过构建：{tag}")
            if args.show:
                print("\n========== Dockerfile ==========")
                print(dockerfile.read_text(encoding="utf-8"))
                print("================================")
            return 0

        print("[INFO] 开始构建（--network host），可能需要几分钟...")
        run_command(
            docker_command(
                [
                    "docker",
                    "build",
                    "--network",
                    "host",
                    "-t",
                    tag,
                    "-f",
                    str(dockerfile),
                    str(build_dir),
                ],
            ),
        )
        print(f"\n[OK] 构建完成：{tag}")
        print("    AgentScope 运行时将复用此镜像缓存。")

        if args.show:
            print("\n========== Dockerfile ==========")
            print(dockerfile.read_text(encoding="utf-8"))
            print("================================")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
