# Whitelist Filter Skill

## 功能描述
快速过滤明确良性 IOC，降低误报。内置 Alexa Top 域名、云厂商 IP 段、安全厂商域名等白名单。

## 输入
- `iocs`: IOC 列表（含 type, value）

## 输出
- `safe_iocs`: 白名单命中的良性 IOC 列表
- `suspicious_iocs`: 需要进一步分析的可疑 IOC 列表
