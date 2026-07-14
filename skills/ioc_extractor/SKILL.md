# IOC Extractor Skill

## 功能描述
从文本中提取各类 IOC（Indicator of Compromise）并分类，支持以下类型：
- IPv4 / IPv6 地址
- 域名
- URL
- MD5 / SHA1 / SHA256 哈希
- 文件路径
- 注册表项
- 邮箱地址

## 输入
- `text`: 要分析的文本内容

## 输出
- `iocs`: IOC 列表，每个包含 type, value, context, line_number
