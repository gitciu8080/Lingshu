# TonyDec（上游镜像）

来源：<https://github.com/jixunmoe/tonydec>

作者：Jixun Wu；许可证：MIT。该目录保留上游解码实现及许可证，供灵枢的
`tonydec` 受控工具调用。上游脚本的命令行接口为：

```bash
python Tools/third_party/tonydec/tonydec.py <input_dir> <output_dir>
```

灵枢 Agent 应优先使用已注册的 `tonydec` 工具，以获得工作目录边界校验、
防覆盖保护和结构化执行结果。
