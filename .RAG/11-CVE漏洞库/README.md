# CVE 漏洞库(导入自旧智能体知识库)

> 关键词:CVE,漏洞库,漏洞利用,中间件漏洞,Web漏洞,网络设备漏洞,反序列化,SQL注入,RCE,文件上传,未授权,指纹识别,漏洞复现
> 本模块整合自旧智能体知识库 `G:\WorkDir\.RAG.old\Vuln\`,收录 649 篇 CVE/漏洞利用文档,按组件类型分目录组织。

## 来源说明

- 原目录:旧知识库 `Vuln/`(649 个 Markdown 文件)
- 适配:将原 YAML frontmatter(漏洞元数据)转换为统一格式——首行 `# 标题`,第二行 `> 关键词:`(由 tags/product/severity/CVE ID 生成),YAML 元数据保留在 ```yaml 代码块中
- 每条目含:漏洞描述 / 影响版本 / 前置条件 / 利用步骤 / Payload / 验证方法 / 修复建议

## 目录导航

| 目录 | 内容 | 示例 |
| --- | --- | --- |
| `middleware/` | 中间件漏洞(数量最多) | shiro、weblogic、tomcat、struts2、spring、solr、redis、rabbitmq、nginx、nacos、jenkins、spring-boot、ofbiz 等 |
| `network/` | 网络设备与安全设备漏洞 | cisco、citrix、fortinet、h3c、huawei、海康威视、深信服、天融信、锐捷、网御星云、dahua |
| `web/` | Web 应用与国产 OA/CMS 漏洞 | 用友、致远、泛微、通达、蓝凌、万户、金蝶、thinkphp、wordpress、drupal、joomla、phpmyadmin、xxl-job、若依 ruoyi、帆软 finereport 等 |

## 检索方式

- **按组件**:`middleware/weblogic/`、`web/yongyou/`(用友)、`web/seeyon-oa/`(致远)等
- **按 CVE 编号**:文件名为 `CVE-YYYY-NNNN.md`,关键词行含 CVE ID
- **按危害等级**:关键词行含 severity(CRITICAL/HIGH/MEDIUM 等)
- **按漏洞类型**:关键词行含 tags(rce/sqli/deserialization/unauth 等)

## 与其他模块联动

- 利用前先了解漏洞原理:`10-漏洞与框架知识/categories/`
- 探测与指纹:`01-渗透测试/信息收集.md`;测试流程:`01-渗透测试/Web渗透测试.md`
- 修复建议对照 `04-安全维护与加固/` 实施加固
- 字典与 payload:`12-Payload库/`、`13-字典库/`

## 合规声明

漏洞利用文档仅用于授权渗透测试、CTF 与靶场复现;未授权利用属违法行为。
