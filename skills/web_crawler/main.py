from __future__ import annotations
from typing import Any
from harness.skill_manager import SkillInfo

info = SkillInfo(
    name="web_crawler",
    description="抓取网页并提取清洗后的正文内容",
    version="1.0.0",
    author="ioc-agent",
    dependencies=["requests", "beautifulsoup4", "readability-lxml"],
)


def execute(url: str, use_playwright: bool = False, **kwargs) -> dict[str, Any]:
    """
    抓取指定 URL 的内容，清洗后返回纯文本正文。
    自动识别 PDF 文件并提取文本。
    """
    if url.lower().endswith(".pdf"):
        return _extract_pdf(url)
    if use_playwright:
        return _crawl_with_playwright(url)
    return _crawl_with_requests(url)


def _crawl_with_requests(url: str) -> dict[str, Any]:
    import requests
    from bs4 import BeautifulSoup
    from readability import Document

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    resp.encoding = resp.apparent_encoding or "utf-8"

    doc = Document(resp.text)
    title = doc.title()
    summary_html = doc.summary()

    soup = BeautifulSoup(summary_html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "aside"]):
        tag.decompose()

    cleaned_text = soup.get_text(separator="\n", strip=True)
    return {
        "cleaned_text": cleaned_text,
        "title": title or "",
        "source_url": url,
    }


def _crawl_with_playwright(url: str) -> dict[str, Any]:
    from bs4 import BeautifulSoup
    from readability import Document

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ImportError("playwright not installed. Run: pip install playwright && playwright install chromium")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle", timeout=30000)
        html = page.content()
        browser.close()

    doc = Document(html)
    title = doc.title()
    summary_html = doc.summary()

    soup = BeautifulSoup(summary_html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "aside"]):
        tag.decompose()

    cleaned_text = soup.get_text(separator="\n", strip=True)
    return {
        "cleaned_text": cleaned_text,
        "title": title or "",
        "source_url": url,
    }


def _extract_pdf(url: str) -> dict[str, Any]:
    """
    下载 PDF 文件并提取文本内容。
    """
    import requests

    try:
        import fitz  # PyMuPDF
    except ImportError:
        raise ImportError(
            "PyMuPDF not installed. Run: pip install PyMuPDF"
        )

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    resp = requests.get(url, headers=headers, timeout=60, stream=True)
    resp.raise_for_status()

    # 用 fitz 从内存中读取 PDF
    pdf_data = resp.content
    doc = fitz.open(stream=pdf_data, filetype="pdf")

    title = doc.metadata.get("title", "") or ""
    total_pages = len(doc)

    # 提取文本，最多处理前 50 页防止过大
    max_pages = min(total_pages, 50)
    text_parts = []
    for page_num in range(max_pages):
        page = doc.load_page(page_num)
        page_text = page.get_text()
        if page_text.strip():
            text_parts.append(page_text)

    doc.close()

    cleaned_text = "\n".join(text_parts).strip()

    if not cleaned_text:
        return {
            "cleaned_text": "",
            "title": title or url.rsplit("/", 1)[-1],
            "source_url": url,
            "warning": "未能提取到文本内容（可能是扫描版 PDF，需要 OCR）",
        }

    return {
        "cleaned_text": cleaned_text,
        "title": title or url.rsplit("/", 1)[-1],
        "source_url": url,
        "total_pages": total_pages,
        "extracted_pages": max_pages,
    }
