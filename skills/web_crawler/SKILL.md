# Web Crawler Skill

## 功能描述
输入 URL，抓取并清洗安全报告正文内容。支持：
- HTML 页面（静态 / 动态 JS 渲染）
- PDF 文件（自动检测 `.pdf` 后缀，提取文本）

## 输入
- `url`: 目标网页 URL（支持 HTML 页面或 PDF 文件）
- `use_playwright`: 是否使用 Playwright 渲染 JS（仅 HTML，默认 false）

## 输出
- `cleaned_text`: 清洗后的纯文本正文
- `title`: 页面标题
- `source_url`: 来源 URL
- `total_pages` / `extracted_pages`: （仅 PDF）总页数和实际提取页数
- `warning`: （仅 PDF 扫描版）提示信息

## 技术栈
- HTML: requests + BeautifulSoup4 + readability-lxml
- PDF: PyMuPDF (fitz)
- 动态渲染: Playwright（可选）
