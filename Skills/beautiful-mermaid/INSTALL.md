# INSTALL — beautiful-mermaid 运行时依赖

本目录是灵枢报告渲染链路的**运行时硬依赖**（`Tools/WeasyReport.py` 与
`Tools/tool_catalog.py` 引用本目录的渲染脚本）。仓库只追踪源码
（SKILL.md / scripts / assets / package.json），不追踪 node_modules。

## 恢复方式

```bash
cd Skills/beautiful-mermaid
npm install        # 一次性；约 94M
```

安装后报告 PDF 中的 Mermaid 图渲染（SVG/PNG）即可用。
未安装时渲染器会优雅降级（图占位不阻断报告生成）。
