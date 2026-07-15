from __future__ import annotations
import os
import time
from typing import Any
from urllib.parse import urlparse
from harness.skill_manager import SkillInfo

info = SkillInfo(
    name="threat_intel",
    description="调用外部威胁情报 API 校验 IOC 信誉",
    version="1.0.0",
    author="ioc-agent",
    dependencies=["requests"],
)


def execute(
    iocs: list[dict],
    source: str = "vt",
    api_key: str | None = None,
    rate_limit: float = 0.5,
    **kwargs,
) -> dict[str, Any]:
    """查询外部威胁情报。"""
    # 按 source 取对应平台的 API Key，避免「配了 OTX 却读 VT 的 key」导致误走 mock
    if not api_key:
        env_var = "VT_API_KEY" if source == "vt" else "OTX_API_KEY"
        api_key = os.getenv(env_var, "")

    if not api_key:
        return _mock_query(iocs, source)

    results = []
    for ioc in iocs:
        ioc_type = ioc.get("type", "")
        ioc_value = ioc.get("value", "")

        result = {
            "value": ioc_value,
            "type": ioc_type,
            "source": source,
            "malicious": "unknown",
            "score": 0,
            "details": "",
        }

        if source == "vt":
            result = _query_virustotal(ioc_type, ioc_value, api_key)
        elif source == "otx":
            result = _query_otx(ioc_type, ioc_value, api_key)

        results.append(result)
        time.sleep(rate_limit)

    return {"total": len(results), "results": results}


def _query_virustotal(ioc_type: str, ioc_value: str, api_key: str) -> dict:
    import requests
    import base64

    # 各 IOC 类型对应的 VT v3 endpoint
    type_map = {
        "ipv4": "ip_addresses",
        "domain": "domains",
        "md5": "files",
        "sha1": "files",
        "sha256": "files",
    }

    # URL 类型不能直接把原始 URL 拼进路径（其中的 :// / 会破坏路径，VT 也识别不了）。
    # VT v3 要求用 base64url（去尾部 =）作为 URL 的标识。
    if ioc_type == "url":
        url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        endpoint = type_map.get(ioc_type, "ip_addresses")
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc_value}"

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            total_engines = sum(stats.values()) if stats else 0

            if malicious_count > 0:
                verdict = "malicious"
            elif suspicious_count > 0:
                verdict = "suspicious"
            else:
                verdict = "benign"

            return {
                "value": ioc_value,
                "type": ioc_type,
                "source": "virustotal",
                "malicious": verdict,
                "score": malicious_count,
                "total_engines": total_engines,
                "details": f"VT: {malicious_count}/{total_engines} engines detected",
            }
        else:
            return {
                "value": ioc_value,
                "type": ioc_type,
                "source": "virustotal",
                "malicious": "unknown",
                "score": 0,
                "details": f"VT API error: HTTP {resp.status_code}",
            }
    except Exception as e:
        return {
            "value": ioc_value,
            "type": ioc_type,
            "source": "virustotal",
            "malicious": "unknown",
            "score": 0,
            "details": f"VT query failed: {e}",
        }


def _query_otx(ioc_type: str, ioc_value: str, api_key: str) -> dict:
    import requests
    import urllib.parse

    type_map = {
        "ipv4": "IPv4",
        "domain": "domain",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
        "email": "email",
    }

    # URL 类型不能直接把原始 URL 拼进路径（其中的 :// / 会破坏路径）。
    # OTX 要求对 URL 做 percent-encoding。
    if ioc_type == "url":
        encoded = urllib.parse.quote(ioc_value, safe="")
        url = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded}/general"
    else:
        otx_type = type_map.get(ioc_type, "IPv4")
        url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc_value}/general"
    headers = {"x-otx-api-key": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            malicious_count = sum(
                1 for p in pulses if p.get("tags") or p.get("references")
            )
            verdict = "malicious" if malicious_count > 0 else "benign"
            return {
                "value": ioc_value,
                "type": ioc_type,
                "source": "otx",
                "malicious": verdict,
                "score": len(pulses),
                "details": f"OTX: found in {len(pulses)} pulses",
            }
        return {
            "value": ioc_value,
            "type": ioc_type,
            "source": "otx",
            "malicious": "unknown",
            "score": 0,
            "details": f"OTX API error: HTTP {resp.status_code}",
        }
    except Exception as e:
        return {
            "value": ioc_value,
            "type": ioc_type,
            "source": "otx",
            "malicious": "unknown",
            "score": 0,
            "details": f"OTX query failed: {e}",
        }


def _mock_query(iocs: list[dict], source: str) -> dict[str, Any]:
    """无 API Key 时的模拟查询。"""
    results = []
    for ioc in iocs:
        results.append({
            "value": ioc.get("value", ""),
            "type": ioc.get("type", ""),
            "source": source,
            "malicious": "unknown",
            "score": 0,
            "details": f"Mock query (no API key configured for {source})",
        })
    return {"total": len(results), "results": results, "mock": True}
