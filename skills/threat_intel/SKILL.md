# Threat Intelligence Query Skill

## 功能描述
调用外部威胁情报 API（VirusTotal、微步在线等）校验 IOC 信誉。

## 输入
- `iocs`: IOC 列表（含 type, value）
- `source`: 情报源（vt / microstep / otx）

## 输出
- `results`: 每个 IOC 的情报查询结果
