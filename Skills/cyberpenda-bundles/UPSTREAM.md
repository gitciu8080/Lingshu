# CyberPenda skill bundles

- 上游仓库：https://github.com/n1majne3/CyberPenda
- 上游目录：`skills/bundles`
- 导入 commit：`900c4740940155df45f5fcebf3cc055648b546a6`
- 导入日期：2026-08-12

此目录保存上游 bundles 的完整快照。灵枢不会在单次任务中加载全部技能，而是由
`agent/Attack.py` 根据任务分类选择相关 bundle，避免无关指令占用模型上下文。

导入时上游仓库根目录未发现统一 LICENSE 文件；bundle 内原有的单独许可证文件均按原样保留。
