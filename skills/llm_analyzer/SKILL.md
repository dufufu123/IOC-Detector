# LLM Semantic Analyzer Skill

## 功能描述
结合上下文语义，通过 LLM 判断 IOC 是否为攻击者控制的恶意资产。支持多种大模型接入。

## 输入
- `iocs`: 待分析的 IOC 列表（含 type, value, context）
- `model`: 模型名称（默认 deepseek-v4-flash）
- `api_key`: API 密钥

## 输出
- `results`: 分析结果列表，每个 IOC 带 malicious 判断和理由
