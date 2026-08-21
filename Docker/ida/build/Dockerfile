# 基于 junegelency/ida-pro-mcp (内含 IDA Pro 9.1 + ida-pro-mcp v1.4.0) 的升级镜像
# 升级内容: idalib 服务器增加 HTTP 上传/状态 API (同端口), 支持 Agent 上传后自动分析
FROM swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/junegelency/ida-pro-mcp:latest

COPY idalib-mcp-upload.py /opt/ida-mcp/idalib-mcp-upload.py

# 上游 v1.4.0 bug 修补: 未命名函数 name=None 会违反 pydantic 输出 schema (str),
# 导致 list_functions 等工具整体报错。改为回退空字符串。
RUN python3 - <<'PYEOF'
from pathlib import Path
p = Path("/usr/local/lib/python3.12/dist-packages/ida_pro_mcp/mcp-plugin.py")
s = p.read_text()
old = "return Function(address=hex(address), name=name, size=hex(fn.end_ea - fn.start_ea))"
new = "return Function(address=hex(address), name=name or \"\", size=hex(fn.end_ea - fn.start_ea))"
assert old in s, "patch target not found"
p.write_text(s.replace(old, new))
print("patched mcp-plugin.py get_function name None fix")
PYEOF

# 依赖 (mcp SDK / starlette / uvicorn / python-multipart / anyio) 均已在基础镜像中, 无需安装
ENV IDA_MCP_UPLOAD_DIR=/analysis/uploads \
    IDA_MCP_MAX_UPLOAD_MB=512

EXPOSE 8745

# 用法与原镜像一致: 第一个参数为要分析的二进制 (可选)。
# 不带参数则以 idle 启动, 等待 POST /upload。
ENTRYPOINT ["python3", "/opt/ida-mcp/idalib-mcp-upload.py", "--host", "0.0.0.0", "--port", "8745"]
