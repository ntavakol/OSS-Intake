"""PDF report (--formats pdf): report.html's page rendered to report.pdf by WeasyPrint.

WeasyPrint is an optional extra (pip install 'oss-intake[pdf]'), as it is large and needs the Pango library from
the system; without it, --formats pdf is refused before any work, with how to add it. The renderer fetches nothing:
the report has no external resources, and any URL in it (a link written by a package or advisory) is refused rather
than opened, so rendering cannot reach the network or read local files. Only data: URIs are read.
"""

from __future__ import annotations

import logging

INSTALL = "pip install 'oss-intake[pdf]' (WeasyPrint; it also needs Pango, see doc.courtbouillon.org/weasyprint)"
# Paper layout: the screen page's width and shadows do not suit A4; tables may run across pages, rows do not. The
# tiles get fixed columns, as the renderer does not fit auto-fit grids.
PAGE_CSS = """
@page{size:A4;margin:14mm 12mm;@bottom-right{content:counter(page) " / " counter(pages);font-size:8pt;color:#57606a}}
body{background:#fff;font-size:9pt}.page{max-width:none;padding:0}
section,header,.tile{box-shadow:none;border:1px solid #ccc;break-inside:auto}
tr,.tile{break-inside:avoid}h2{break-after:avoid}thead{display:table-header-group}
.wrap{overflow:visible}table{width:100%}td,th{padding:3px 5px}td{overflow-wrap:anywhere}
th{white-space:normal;font-size:8pt}
.tiles{grid-template-columns:repeat(4,1fr);gap:8px}.grid2{grid-template-columns:1fr}
"""


def missing() -> str | None:
    """Why a PDF cannot be written here, or None when it can."""
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        return f"--formats pdf needs the pdf extra: {INSTALL}"
    except OSError as exc:  # WeasyPrint is installed but the system's Pango is not
        return f"--formats pdf: WeasyPrint is installed but cannot load its system libraries ({exc}): {INSTALL}"
    return None


def _fetcher():
    """A URL fetcher that reads data: URIs and refuses everything else (http, https, file, ...)."""
    from weasyprint import urls

    if hasattr(urls, "URLFetcher"):  # newer WeasyPrint
        return urls.URLFetcher(allowed_protocols=("data",), allow_redirects=False)

    def fetch(url: str, *args, **kwargs):  # earlier versions take a function
        if not url.startswith("data:"):
            raise ValueError("oss-intake fetches nothing while rendering the PDF")
        return urls.default_url_fetcher(url, *args, **kwargs)

    return fetch


def render(html_text: str) -> bytes:
    import weasyprint

    fetcher = _fetcher()
    quiet = [logging.getLogger(n) for n in ("weasyprint", "fontTools")]
    levels = [lg.level for lg in quiet]
    for lg in quiet:  # unsupported CSS and refused URLs are not the user's concern
        lg.setLevel(logging.ERROR)
    try:
        # The paper layout goes last in the head, so it wins over the screen styles it replaces.
        page = html_text.replace("</head>", f"<style>{PAGE_CSS}</style></head>", 1)
        pdf = weasyprint.HTML(string=page, url_fetcher=fetcher, base_url=None).write_pdf()
    except Exception as exc:  # noqa: BLE001 - a renderer or system library failure, said plainly (exit 1)
        raise OSError(f"the PDF report could not be rendered by WeasyPrint: {type(exc).__name__}: {exc}") from exc
    finally:
        for lg, level in zip(quiet, levels, strict=True):
            lg.setLevel(level)
    if not isinstance(pdf, bytes):
        raise OSError("WeasyPrint returned no PDF")
    return pdf
