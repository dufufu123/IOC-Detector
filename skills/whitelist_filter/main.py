from __future__ import annotations
import os
import ipaddress
from pathlib import Path
from typing import Any
from harness.skill_manager import SkillInfo

info = SkillInfo(
    name="whitelist_filter",
    description="通过白名单快速过滤明确良性 IOC",
    version="1.0.0",
    author="ioc-agent",
    dependencies=[],
)

# ── 内置白名单 ────────────────────────────────────────────

# 常见安全/云厂商域名白名单
SAFE_DOMAINS: set[str] = {
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "azure.com", "office365.com",
    "amazon.com", "amazonaws.com", "aws.com",
    "cloudflare.com", "cloudflarestatus.com",
    "github.com", "githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "apple.com", "icloud.com",
    "facebook.com", "fbcdn.net",
    "twitter.com", "x.com",
    "linkedin.com",
    "docker.com", "docker.io",
    "python.org", "pypi.org",
    "npmjs.com", "nodejs.org",
    "nginx.org", "apache.org",
    "mysql.com", "postgresql.org",
    "redis.io", "elastic.co",
    "nsfocus.com", "venustech.com.cn",  # 绿盟、启明等安全厂商
    "dbappsecurity.com.cn",  # 安恒
    "qianxin.com",  # 奇安信
    "360.cn", "360.com",
    "tencent.com", "qq.com",
    "alibaba.com", "aliyun.com",
    "baidu.com", "baiducontent.com",
    "huawei.com", "huaweicloud.com",
    "163.com", "126.com",
    "sina.com.cn", "sohu.com",
    "cnnvd.org.cn", "cnvd.org.cn",
    "nvd.nist.gov", "cve.mitre.org",
    "virustotal.com", "otx.alienvault.com",
    "ibm.com", "oracle.com", "cisco.com",
    "sophos.com", "mcafee.com", "symantec.com",
    "trendmicro.com", "kaspersky.com",
    "eset.com", "paloaltonetworks.com",
    "checkpoint.com", "fortinet.com",
    "symantec.com", "broadcom.com",              # Symantec / Broadcom
    "talosintelligence.com",                      # Talos
    "unit42.paloaltonetworks.com",                # Unit 42
    "securelist.com",                             # Kaspersky Securelist
    "blog.qualys.com", "qualys.com",
    "crowdstrike.com", "blog.crowdstrike.com",
    "mandiant.com",
    "fireeye.com",
    "proofpoint.com", "blog.proofpoint.com",
    "sonicwall.com", "blog.sonicwall.com",
    "welivesecurity.com",                         # ESET
    "threatpost.com",
    "bleepingcomputer.com",
    "securityweek.com",
    "darkreading.com",
    "infosecurity-magazine.com",
    "thehackernews.com",
    "mp.weixin.qq.com", "weixin.qq.com",          # 微信公众号
    "wechat.com", "myexternalip.com",             # 外网IP查询服务
}

# 常见 CDN / 公共 DNS IP 段（CIDR 格式）
SAFE_IP_RANGES: list[str] = [
    "8.8.8.0/24", "8.8.4.0/24",        # Google DNS
    "1.1.1.0/24", "1.0.0.0/24",        # Cloudflare DNS
    "208.67.222.0/24", "208.67.220.0/24",  # OpenDNS
    "9.9.9.0/24",                       # Quad9 DNS
    # 部分 AWS 区域
    "52.0.0.0/8", "54.0.0.0/8",
    # 部分 Azure
    "13.0.0.0/8", "20.0.0.0/8",
    # 部分 GCP
    "35.0.0.0/8", "34.0.0.0/8",
]

# Windows 系统标准路径白名单（出现在安全报告中但非 IOC）
SAFE_FILEPATHS: set[str] = {
    # Windows 系统目录
    r"C:\Windows", r"C:\Windows\System32",
    r"C:\Windows\System", r"C:\Windows\SysWOW64",
    r"C:\Windows\Temp", r"C:\Windows\Tasks",
    r"C:\ProgramData", r"C:\Program Files",
    r"C:\Program Files (x86)", r"C:\Users",
    r"C:\Users\Public", r"C:\Users\Default",
    r"C:\Documents and Settings",
    r"C:\PerfLogs", r"C:\Recovery",
    r"C:\Windows\System32\drivers",
    r"C:\Windows\System32\config",
    r"C:\Windows\System32\Tasks",
    r"C:\Windows\Microsoft.NET",
    r"C:\Windows\System32\wbem",
    r"C:\Windows\System32\WindowsPowerShell",
    # Unix 标准目录
    "/etc", "/usr", "/bin", "/sbin", "/lib",
    "/usr/bin", "/usr/lib", "/usr/local",
    "/usr/share", "/var", "/var/log", "/var/tmp",
    "/tmp", "/home", "/root", "/opt",
    "/proc", "/sys", "/dev",
    "/etc/init.d", "/etc/cron",
    "/etc/systemd", "/etc/rc.d",
}


def _is_safe_filepath(fp: str) -> bool:
    """判断文件路径是否为系统标准路径。"""
    fp_lower = fp.lower().rstrip("\\/")
    if fp_lower in {p.lower() for p in SAFE_FILEPATHS}:
        return True
    # 检查是否是系统路径的子路径
    for safe in SAFE_FILEPATHS:
        if fp_lower.startswith(safe.lower() + "\\") or fp_lower.startswith(safe.lower() + "/"):
            return True
    return False


def _load_custom_whitelist(data_dir: str) -> set[str]:
    """从 data 目录加载自定义白名单。"""
    custom_domains: set[str] = set()
    custom_path = Path(data_dir) / "custom_whitelist.txt"
    if custom_path.exists():
        with open(custom_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    custom_domains.add(line.lower())
    return custom_domains


def _is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in SAFE_IP_RANGES:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        return ip.is_private or ip.is_loopback or ip.is_multicast
    except ValueError:
        return False


def _is_whitelisted(domain: str, whitelist: set[str]) -> bool:
    domain = domain.lower()
    if domain in whitelist:
        return True
    # 检查子域名（如 sub.example.com 匹配 example.com）
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in whitelist:
            return True
    return False


def execute(iocs: list[dict], data_dir: str | None = None, **kwargs) -> dict[str, Any]:
    """白名单过滤 IOC 列表。"""
    whitelist = SAFE_DOMAINS.copy()
    if data_dir and os.path.isdir(data_dir):
        whitelist |= _load_custom_whitelist(data_dir)

    safe_iocs: list[dict] = []
    suspicious_iocs: list[dict] = []

    for ioc in iocs:
        ioc_type = ioc.get("type", "")
        ioc_value = ioc.get("value", "")

        is_safe = False

        if ioc_type in ("domain", "url"):
            if ioc_type == "url":
                from urllib.parse import urlparse
                hostname = urlparse(ioc_value).hostname or ""
            else:
                hostname = ioc_value
            is_safe = _is_whitelisted(hostname, whitelist)

        elif ioc_type == "ipv4":
            is_safe = _is_safe_ip(ioc_value)

        elif ioc_type in ("filepath",):
            is_safe = _is_safe_filepath(ioc_value)

        if is_safe:
            safe_iocs.append(ioc)
        else:
            suspicious_iocs.append(ioc)

    return {
        "total": len(iocs),
        "safe_count": len(safe_iocs),
        "suspicious_count": len(suspicious_iocs),
        "safe_iocs": safe_iocs,
        "suspicious_iocs": suspicious_iocs,
    }
