from __future__ import annotations
import re
from typing import Any
from harness.skill_manager import SkillInfo

info = SkillInfo(
    name="ioc_extractor",
    description="从文本中提取各类 IOC 指标并分类",
    version="1.0.0",
    author="ioc-agent",
    dependencies=[],
)

# ── 正则模式 ──────────────────────────────────────────────

# IPv4：严格校验 0-255 范围
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# 域名（不捕获 IP 和常见伪域名）
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:com|cn|net|org|edu|gov|info|io|co|cc|top|xyz|'
    r'club|shop|online|site|vip|tech|store|me|tv|biz|'
    r'mil|int|pro|name|dev|app|ai|link|win|bid)\b',
    re.IGNORECASE,
)

# URL
URL_PATTERN = re.compile(
    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    r'(?::\d+)?(?:/[-\w$.+!*\'(),;:@&=?/~#%]*)?',
    re.IGNORECASE,
)

# MD5
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')

# SHA1
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')

# SHA256
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

# 文件路径（Windows + Unix）
# 注：同时排除 Unicode 弯引号（“”），网页中常出现
FILEPATH_PATTERN = re.compile(
    r'(?:[a-zA-Z]:\\[^\s:;*?"<>|“”]+'
    r'|/[^\s:;*?"<>|“”]+)'
)

# 邮箱
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

# 注册表项
REGISTRY_PATTERN = re.compile(
    r'(?:HKEY_[A-Z_]+|HK[A-Z]{2})\\[a-zA-Z0-9_\\]+'
)

# IPv6（简化版）
IPV6_PATTERN = re.compile(
    r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b'
    r'|\b(?:[a-fA-F0-9]{1,4}:){1,7}:'
    r'|\b(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}\b'
    r'|\b::(?:[a-fA-F0-9]{1,4}:){1,6}[a-fA-F0-9]{1,4}\b'
)


# 上下文长度上限：超过则视为句子切分失效（如无标点的纯哈希列表），
# 回退为按行取前后 LINE_CONTEXT_WINDOW 行。
# 定 1500 是为放过「切分成功但本就偏大」的合法上下文--例如 sha512
# (128 字符) 带 5 个 window 的正常上下文约 1000+ 字符，不应被降级。
MAX_CONTEXT_CHARS = 800
LINE_CONTEXT_WINDOW = 3


def _get_context(text: str, pos: int, window: int = 2) -> str:
    """获取 IOC 前后各 window 句的上下文。

    先按句末标点切分取前后 window 句；若结果过长（> MAX_CONTEXT_CHARS，
    常见于无标点的纯列表/哈希串——会把整篇正文都当成上下文），改按行切分，
    取 IOC 所在行前后各 LINE_CONTEXT_WINDOW 行。
    """
    context = _get_context_by_sentence(text, pos, window)
    if len(context) <= MAX_CONTEXT_CHARS:
        return context
    return _get_context_by_line(text, pos, LINE_CONTEXT_WINDOW)


def _get_context_by_sentence(text: str, pos: int, window: int) -> str:
    """按句末标点切分，取 IOC 所在句前后各 window 句。"""
    sentences = re.split(r'(?<=[。！？.!?])\s*', text)
    char_count = 0
    target_sentence_idx = -1
    for i, s in enumerate(sentences):
        char_count += len(s)
        if char_count > pos:
            target_sentence_idx = i
            break
    start = max(0, target_sentence_idx - window)
    end = min(len(sentences), target_sentence_idx + window + 1)
    return "".join(sentences[start:end]).strip()


def _get_context_by_line(text: str, pos: int, window: int) -> str:
    """按行切分，取 IOC 所在行前后各 window 行（句子切分失效时的回退策略）。"""
    lines = text.split("\n")
    if not lines:
        return text.strip()
    # pos 之前的换行符个数即所在行索引（对 \n / \r\n 均准确）
    line_idx = min(text.count("\n", 0, pos), len(lines) - 1)
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window + 1)
    # 去除 \r\n 残留的 \r
    return "\n".join(line.rstrip("\r") for line in lines[start:end]).strip()


def _deduplicate(iocs: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            result.append(ioc)
        else:
            for existing in result:
                if existing["type"] == ioc["type"] and existing["value"] == ioc["value"]:
                    existing["count"] = existing.get("count", 1) + 1
                    break
    return result


# ── 防解析标记替换规则 ──────────────────────────
# 安全报告常用 [.]、hxxp 等方式防解析，需先还原
DEFANG_REPLACEMENTS = [
    (r'\[\.\]', '.'),
    (r'\[:\]', ':'),
    (r'\[://\]', '://'),
    (r'\bhxxps?://', lambda m: 'http' + m.group()[4:]),  # hxxp → http, hxxps → https
    (r'\[\]', ''),  # 空的防解析标记
]


def _normalize_text(text: str) -> str:
    """预处理文本，还原防解析标记，使正则能正确匹配。"""
    for pattern, replacement in DEFANG_REPLACEMENTS:
        text = re.sub(pattern, replacement, text)
    return text


# 中文字符范围（CJK 统一表意文字）
_CJK_RANGE = re.compile(r'[一-鿿]')


def _has_cjk(s: str) -> bool:
    return bool(_CJK_RANGE.search(s))


def execute(text: str, **kwargs) -> dict[str, Any]:
    """从文本中提取 IOC 指标。"""
    # 先还原防解析标记，使正则能匹配 defanged IOC
    text = _normalize_text(text)
    iocs = []

    # URL（优先于域名提取）
    for m in URL_PATTERN.finditer(text):
        iocs.append({
            "type": "url",
            "value": m.group(),
            "context": _get_context(text, m.start()),
            "start": m.start(),
        })

    # IPv4
    for m in IPV4_PATTERN.finditer(text):
        iocs.append({
            "type": "ipv4",
            "value": m.group(),
            "context": _get_context(text, m.start()),
            "start": m.start(),
        })

    # 域名（排除已作为 URL 提取的）
    url_values = {i["value"] for i in iocs}
    for m in DOMAIN_PATTERN.finditer(text):
        domain = m.group().lower()
        if domain not in url_values and not any(
            domain in uv for uv in url_values
        ):
            iocs.append({
                "type": "domain",
                "value": domain,
                "context": _get_context(text, m.start()),
                "start": m.start(),
            })

    # 哈希（按长度区分）
    for m in MD5_PATTERN.finditer(text):
        iocs.append({
            "type": "md5",
            "value": m.group().lower(),
            "context": _get_context(text, m.start()),
            "start": m.start(),
        })
    for m in SHA1_PATTERN.finditer(text):
        iocs.append({
            "type": "sha1",
            "value": m.group().lower(),
            "context": _get_context(text, m.start()),
            "start": m.start(),
        })
    for m in SHA256_PATTERN.finditer(text):
        iocs.append({
            "type": "sha256",
            "value": m.group().lower(),
            "context": _get_context(text, m.start()),
            "start": m.start(),
        })

    # 邮箱
    for m in EMAIL_PATTERN.finditer(text):
        iocs.append({
            "type": "email",
            "value": m.group(),
            "context": _get_context(text, m.start()),
            "start": m.start(),
        })

    # 文件路径（Windows + Unix）
    for m in FILEPATH_PATTERN.finditer(text):
        val = m.group()
        # 排除过短的路径（至少包含一个分隔符后的名称）
        if len(val) >= 6:
            # 排除以 // 开头的类 URL 路径（如 //domain.com/path 会被误匹配）
            if val.startswith("//") and "." in val[2:].split("/")[0]:
                continue
            # 排除包含中文的路径片段（通常是文案碎片而非真实路径）
            if _has_cjk(val):
                continue
            # 排除单一段的路径（如 /foo 这种不可能是文件路径）
            if val.startswith("/") and val.count("/") < 2:
                continue
            iocs.append({
                "type": "filepath",
                "value": val,
                "context": _get_context(text, m.start()),
                "start": m.start(),
            })

    # 注册表项
    for m in REGISTRY_PATTERN.finditer(text):
        iocs.append({
            "type": "registry",
            "value": m.group(),
            "context": _get_context(text, m.start()),
            "start": m.start(),
        })

    # IPv6
    for m in IPV6_PATTERN.finditer(text):
        iocs.append({
            "type": "ipv6",
            "value": m.group().lower(),
            "context": _get_context(text, m.start()),
            "start": m.start(),
        })

    # 去重 & 排序
    iocs = _deduplicate(iocs)
    iocs.sort(key=lambda x: x["start"])

    # 去掉 start 字段（内部使用）
    for ioc in iocs:
        del ioc["start"]

    return {
        "total": len(iocs),
        "iocs": iocs,
    }
