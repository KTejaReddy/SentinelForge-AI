"""Browser testing backend.

Preferred engine: Playwright (headless Chromium) - real browser with
console-error capture, network-failure capture, form discovery, workflow
walking and screenshots.

Fallback engine: deterministic HTTP crawl (links + forms) when Playwright
isn't installed - still real results, with a recorded limitation.

Both engines only ever navigate the sandboxed application's loopback URL.
"""
from __future__ import annotations

import re
import time
from typing import Any

from events import log
from services.probes.http import probe
from services.scan_context import ScanContext
from tools.base import ToolAdapter, make_finding

try:
    from playwright.sync_api import sync_playwright  # type: ignore
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

MAX_PAGES = 25
MAX_DEPTH = 3


class PlaywrightProbeAdapter(ToolAdapter):
    name = "browser"
    display_name = "Browser Agent"

    def detect(self) -> bool:
        return HAS_PLAYWRIGHT

    def version(self) -> str | None:
        try:
            import playwright
            return getattr(playwright, "__version__", "installed")
        except Exception:
            return None

    def install_hint(self) -> str:
        return "pip install playwright && playwright install chromium - falls back to HTTP crawl"

    def run(self, ctx: ScanContext) -> list[dict[str, Any]]:
        base_url = ctx.runtime.get("base_url")
        if not base_url:
            ctx.add_limitation("Browser testing skipped: application did not start")
            return []
        if HAS_PLAYWRIGHT:
            try:
                return self._run_playwright(ctx, base_url)
            except Exception as exc:
                ctx.add_limitation(f"Playwright browser failed to launch ({str(exc)[:200]}) - used HTTP crawl fallback")
                return self._run_crawl(ctx, base_url)
        ctx.add_limitation("Playwright unavailable - browser agent used HTTP crawl fallback")
        return self._run_crawl(ctx, base_url)

    # ------------------------------------------------------------------ playwright

    def _run_playwright(self, ctx: ScanContext, base_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        artifacts = ctx.workspace / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        visited: set[str] = set()
        console_errors: dict[str, int] = {}
        page_errors: list[str] = []
        failed_requests: dict[str, int] = {}
        forms_found: list[dict[str, Any]] = []
        links_found: set[str] = set()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
                page = browser.new_page(viewport={"width": 1280, "height": 800})
                page.on("console", lambda msg: _track(console_errors, msg.type, msg.text) if msg.type == "error" else None)
                page.on("pageerror", lambda exc: page_errors.append(str(exc)[:400]))
                page.on("requestfailed", lambda req: _track(failed_requests, "failed", req.url) if not req.url.startswith("data:") else None)

                def walk(url: str, depth: int) -> None:
                    if depth > MAX_DEPTH or len(visited) >= MAX_PAGES:
                        return
                    if url in visited:
                        return
                    visited.add(url)
                    try:
                        page.goto(url, timeout=15000, wait_until="domcontentloaded")
                        time.sleep(0.6)
                    except Exception as exc:
                        page_errors.append(f"nav {url}: {str(exc)[:200]}")
                        return
                    if len(visited) == 1:
                        try:
                            page.screenshot(path=str(artifacts / "home.png"), full_page=False)
                        except Exception:
                            pass
                    for form in page.query_selector_all("form"):
                        name = (form.get_attribute("name") or form.get_attribute("id") or "")[:80]
                        action = (form.get_attribute("action") or url)[:200]
                        methods = (form.get_attribute("method") or "get").upper()
                        inputs = [i.get_attribute("name") for i in form.query_selector_all("input, select, textarea") if i.get_attribute("name")]
                        forms_found.append({"action": action, "method": methods, "inputs": inputs, "page": url, "name": name})
                    for a in page.query_selector_all("a[href]"):
                        href = a.get_attribute("href") or ""
                        full = _resolve(base_url, href)
                        if full and full.startswith(base_url) and full not in visited:
                            links_found.add(full)
                    for href in list(links_found):
                        if len(visited) < MAX_PAGES:
                            walk(href, depth + 1)
                        else:
                            break

                walk(base_url, 0)
                browser.close()
        except Exception:
            raise  # let run() fall back to the HTTP crawl

        # console / page / network errors
        if console_errors:
            total = sum(console_errors.values())
            findings.append(make_finding(
                title=f"Browser console errors ({total})",
                category="reliability", severity="MEDIUM", confidence=0.85, source="browser",
                affected_component=base_url,
                description="JavaScript console errors observed while browsing: " + ", ".join(f"{k} ({v})" for k, v in list(console_errors.items())[:8]),
                evidence={"tool": "browser", "console_errors": dict(list(console_errors.items())[:20])},
                reproduction={"steps": ["Open " + base_url + " and check the console"], "tool": "browser"},
            ))
        if page_errors:
            findings.append(make_finding(
                title="Page-level JavaScript exceptions",
                category="reliability", severity="MEDIUM", confidence=0.85, source="browser",
                affected_component=base_url,
                description="Uncaught exceptions while browsing:\n" + "\n".join(page_errors[:6]),
                evidence={"tool": "browser", "page_errors": page_errors[:10]},
                reproduction={"steps": ["Browse the app and observe uncaught exceptions"], "tool": "browser"},
            ))
        if failed_requests:
            total = sum(failed_requests.values())
            findings.append(make_finding(
                title=f"Failed network requests ({total})",
                category="reliability", severity="LOW", confidence=0.8, source="browser",
                affected_component=base_url,
                description="Network requests that failed while browsing.",
                evidence={"tool": "browser", "failed_requests": dict(list(failed_requests.items())[:10])},
                reproduction={"steps": ["Browse the app and observe failed requests"], "tool": "browser"},
            ))
        ctx.tool_results["browser"] = {
            "engine": "playwright",
            "pages_visited": len(visited),
            "links": len(links_found),
            "forms": len(forms_found),
            "screenshot": str(artifacts / "home.png"),
        }
        log(ctx.scan_id, f"Browser: visited {len(visited)} pages, found {len(forms_found)} forms, {len(links_found)} links")
        if forms_found:
            findings.append(make_finding(
                title=f"Discovered {len(forms_found)} form(s) in the UI",
                category="web_security", severity="INFO", confidence=0.9, source="browser",
                affected_component=base_url,
                description="Forms discovered by the browser agent: " + "; ".join(
                    f"{f['name'] or 'form'} → {f['action']} [{f['method']}] ({', '.join(f['inputs'][:6])})" for f in forms_found[:8]),
                evidence={"tool": "browser", "forms": forms_found[:10]},
                reproduction={"steps": ["Browse the application"], "tool": "browser"},
            ))
        return findings

    # --------------------------------------------------------------------- crawl

    def _run_crawl(self, ctx: ScanContext, base_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        visited: set[str] = set()
        forms: list[dict[str, Any]] = []
        links: set[str] = set()
        try:
            from bs4 import BeautifulSoup
        except Exception:
            ctx.add_limitation("Crawl fallback needs beautifulsoup4 (pip install beautifulsoup4)")
            return findings

        queue = [base_url]
        while queue and len(visited) < MAX_PAGES:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = probe("GET", url, timeout_s=8)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            soup = BeautifulSoup(resp.text or "", "html.parser")
            for form in soup.find_all("form"):
                inputs = [i.get("name") for i in form.find_all(["input", "select", "textarea"]) if i.get("name")]
                forms.append({"action": form.get("action") or url, "method": (form.get("method") or "get").upper(), "inputs": inputs, "page": url})
            for a in soup.find_all("a", href=True):
                full = _resolve(base_url, a["href"])
                if full and full.startswith(base_url) and full not in visited and full not in links:
                    links.add(full)
                    queue.append(full)
        ctx.tool_results["browser"] = {"engine": "crawl", "pages_visited": len(visited), "links": len(links), "forms": len(forms)}
        log(ctx.scan_id, f"Browser (crawl): visited {len(visited)} pages, {len(forms)} forms")
        if forms:
            findings.append(make_finding(
                title=f"Discovered {len(forms)} form(s) in the UI",
                category="web_security", severity="INFO", confidence=0.9, source="browser",
                affected_component=base_url,
                description="Forms discovered by the crawl agent: " + "; ".join(
                    f"→ {f['action']} [{f['method']}] ({', '.join(f['inputs'][:6])})" for f in forms[:8]),
                evidence={"tool": "browser", "forms": forms[:10]},
                reproduction={"steps": ["Browse the application"], "tool": "browser"},
            ))
        return findings


def _track(counter: dict[str, int], key: str, value: str) -> None:
    short = (value or "")[:180]
    counter[short] = counter.get(short, 0) + 1


def _resolve(base: str, href: str) -> str | None:
    from urllib.parse import urljoin

    if href.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    full = urljoin(base, href)
    if not full.startswith(("http://", "https://")):
        return None
    return full.split("#")[0]
