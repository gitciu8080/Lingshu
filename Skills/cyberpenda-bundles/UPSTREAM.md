# CyberPenda skill bundles

- 上游仓库：https://github.com/n1majne3/CyberPenda
- 上游目录：`skills/bundles`
- 导入 commit：`900c4740940155df45f5fcebf3cc055648b546a6`
- 导入日期：2026-08-12

此目录保存上游 bundles 的完整快照。灵枢不会在单次任务中加载全部技能，而是由
`agent/Attack.py` 根据任务分类选择相关 bundle，避免无关指令占用模型上下文。

导入时上游仓库根目录未发现统一 LICENSE 文件；bundle 内原有的单独许可证文件均按原样保留。

## 本地偏差记录（相对上游快照）

- 2026-10-29：删除 reverse-skill-router/{field-journal,ops,CONTRIBUTING.md}（上游作者个人
  实战流水账与运维文件，与技能功能无关）；删除 diagram-generator/README.md（与同目录
  SKILL.md 并存的冗余文件）。技能本体未改动。
