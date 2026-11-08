"""--formats pdf: report.html rendered by WeasyPrint (the optional pdf extra). CI does not install WeasyPrint (it
needs Pango from the system), so the wiring is tested with a stand-in; the real renderer is tested where installed."""

import json
import sys
import types

import pytest

from oss_intake import cli, report_pdf

AS_OF = "2026-11-08"


def _scan(tmp_path, fixtures, *extra, http=None):
    out = tmp_path / "out"
    code = cli.main(["--image", "owner/app:1.0", "--out", str(out), "--from-trivy-json", str(fixtures / "trivy.json"),
                     "--from-grype-json", str(fixtures / "grype.json"), "--offline", "--as-of", AS_OF, *extra],
                    http=http)
    return code, out


@pytest.fixture
def stand_in(monkeypatch):
    """A WeasyPrint stand-in that records what it was given."""
    seen: dict = {}
    wp = types.ModuleType("weasyprint")
    urls = types.ModuleType("weasyprint.urls")

    class URLFetcher:
        def __init__(self, **kwargs):
            seen["fetcher"] = kwargs

    class HTML:
        def __init__(self, string=None, url_fetcher=None, base_url=None):
            seen.update(html=string, url_fetcher=url_fetcher, base_url=base_url)

        def write_pdf(self):
            return b"%PDF-1.7 stand-in"

    urls.URLFetcher, wp.HTML, wp.urls = URLFetcher, HTML, urls
    monkeypatch.setitem(sys.modules, "weasyprint", wp)
    monkeypatch.setitem(sys.modules, "weasyprint.urls", urls)
    return seen


def test_pdf_report_is_the_html_report_rendered_with_nothing_fetched(tmp_path, fixtures, stand_in):
    """Backlog (done 8 Nov): a PDF report. It is the HTML report's page with a paper layout, and the renderer may
    read only data: URIs, so a link in the report cannot make it reach the network or read a local file."""
    code, out = _scan(tmp_path, fixtures, "--formats", "pdf")
    assert code == cli.EXIT_OK
    assert (out / "report.pdf").read_bytes() == b"%PDF-1.7 stand-in"
    assert not (out / "report.html").exists()  # the PDF does not need the HTML file
    assert "OSS intake assessment" in stand_in["html"] and "@page" in stand_in["html"]
    assert stand_in["fetcher"] == {"allowed_protocols": ("data",), "allow_redirects": False}
    assert stand_in["base_url"] is None
    files = json.loads((out / ".oss-intake-files.json").read_text(encoding="utf-8"))["files"]
    assert "report.pdf" in files


def test_pdf_without_the_extra_is_refused_before_any_work(tmp_path, fixtures, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "weasyprint", None)  # import fails as if it were not installed
    code, out = _scan(tmp_path, fixtures, "--formats", "html,pdf")
    assert code == cli.EXIT_USAGE and "pip install 'oss-intake[pdf]'" in capsys.readouterr().err
    assert not out.exists()


def test_a_stale_pdf_is_removed_when_pdf_is_no_longer_asked_for(tmp_path, fixtures, stand_in):
    code, out = _scan(tmp_path, fixtures, "--formats", "pdf")
    assert (out / "report.pdf").exists()
    code, out = _scan(tmp_path, fixtures, "--formats", "html")
    assert code == cli.EXIT_OK and not (out / "report.pdf").exists()


def test_the_real_renderer_reads_data_uris_and_nothing_else():
    """With WeasyPrint installed: a file:// or http URL in the page is refused, a data: URI is read, and the
    result is a PDF."""
    pytest.importorskip("weasyprint")
    fetch = report_pdf._fetcher()
    call = getattr(fetch, "fetch", fetch)
    for url in ("file:///etc/passwd", "http://127.0.0.1:9/x.css", "https://example.invalid/x.png"):
        with pytest.raises(ValueError):
            call(url)
    pdf = report_pdf.render('<html><head></head><body><img src="file:///etc/passwd">'
                            '<link rel="stylesheet" href="http://127.0.0.1:9/x.css"><p>ok</p></body></html>')
    assert pdf.startswith(b"%PDF")
