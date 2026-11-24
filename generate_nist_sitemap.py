#!/usr/bin/env python3
"""
NIST Cybersecurity & Computing Standards Sitemap Generator
Discovers all official NIST Special Publications (SP 800, 1800, 500), FIPS,
NISTIRs, CSWPs, and AI Standards from the NIST Computer Security Resource Center (CSRC)
and generates Onyx-compatible flat XML sitemaps.
"""

import os
import sys
import re
import json
import time
import threading
import requests
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime, timezone
from urllib.parse import urljoin
import concurrent.futures

BASE_URL = "https://csrc.nist.gov"
SEARCH_URL = f"{BASE_URL}/publications/search"

SERIES_FILTERS = ["FIPS", "SP", "IR", "CSWP", "AI"]
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
}

MAX_WORKERS = 8
MAX_RETRIES = 4
_thread_local = threading.local()


def get_session() -> requests.Session:
    """Return a thread-local requests.Session with HTTP keep-alive."""
    sess = getattr(_thread_local, "session", None)
    if sess is None:
        sess = requests.Session()
        sess.headers.update(HEADERS)
        _thread_local.session = sess
    return sess


def normalize_pdf_url(pdf_url):
    """Normalize relative CSRC PDF paths to absolute https://csrc.nist.gov/... URLs."""
    if not pdf_url:
        return None
    u = pdf_url.strip()
    if not u:
        return None
    if u.startswith("/"):
        return urljoin(BASE_URL, u)
    return u


def fetch_search_page(page_num, ipp=100, max_retries=MAX_RETRIES):
    """Fetches a single search result page from CSRC with retries and backoff."""
    params = [("ipp-lg", str(ipp)), ("page", str(page_num))]
    for s in SERIES_FILTERS:
        params.append(("series-lg", s))

    url = f"{SEARCH_URL}?" + "&".join(f"{k}={v}" for k, v in params)
    last_err = None
    sess = get_session()
    for attempt in range(1, max_retries + 1):
        try:
            resp = sess.get(url, timeout=20)
            if resp.status_code == 200 and "result-" in resp.text:
                return resp.text
            last_err = f"HTTP {resp.status_code}"
        except Exception as e:
            last_err = str(e)
        if attempt < max_retries:
            wait = min(2 ** attempt, 12)
            print(f"  [retry {attempt}/{max_retries}] search page {page_num} failed ({last_err}); sleeping {wait}s...")
            time.sleep(wait)
    raise RuntimeError(f"Failed to fetch CSRC search page {page_num} after {max_retries} attempts: {last_err}")


def parse_search_records(html):
    """Extracts publication rows from CSRC search HTML."""
    records = []
    rows = re.findall(r'<tr id=\"result-\d+\".*?</tr>', html, re.DOTALL)
    for row in rows:
        series_m = re.search(r'id=\"pub-series-\d+\">([^<]+)<', row)
        num_m = re.search(r'id=\"pub-number-\d+\">([^<]+)<', row)
        title_m = re.search(r'<a href=\"([^\"]+)\"[^>]*>([^<]+)</a>', row)
        status_m = re.search(r'id=\"pub-status-\d+\">\s*([^<\s]+)', row)
        date_m = re.search(r'id=\"pub-release-date-\d+\">\s*([^<\s]+)', row)

        if title_m:
            link = title_m.group(1).strip()
            title = title_m.group(2).strip()
            series = series_m.group(1).strip() if series_m else ""
            number = num_m.group(1).strip() if num_m else ""
            status = status_m.group(1).strip() if status_m else "Final"
            rel_date = date_m.group(1).strip() if date_m else ""

            records.append({
                "series": series,
                "number": number,
                "title": title,
                "status": status,
                "date": rel_date,
                "detail_path": link,
                "detail_url": f"{BASE_URL}{link}" if link.startswith("/") else link
            })
    return records


def extract_pdf_from_detail(detail_url, max_retries=MAX_RETRIES):
    """
    Fetches publication detail page with exponential backoff and extracts direct PDF / DOI URL.
    Returns (fetch_ok: bool, pdf_url: Optional[str], desc: str).
    """
    sess = get_session()
    for attempt in range(1, max_retries + 1):
        try:
            r = sess.get(detail_url, timeout=18)
            if r.status_code in (404, 410):
                return True, None, ""
            if r.status_code != 200:
                if attempt < max_retries:
                    time.sleep(min(1.5 * (2 ** (attempt - 1)), 12))
                    continue
                return False, None, ""

            html = r.text
            pdf_url = None

            # 1. Check local download link
            m_local = re.search(r'id=[\"\']pub-local-download-link[\"\'][^>]*href=[\"\']([^\"\']+)[\"\']', html)
            if not m_local:
                m_local = re.search(r'href=[\"\']([^\"\']+\.pdf)[\"\'][^>]*id=[\"\']pub-local-download-link[\"\']', html)
            if m_local and (m_local.group(1).lower().endswith(".pdf") or "nvlpubs.nist.gov" in m_local.group(1)):
                pdf_url = m_local.group(1)

            # 2. Check citation_pdf_url meta tag
            if not pdf_url:
                m_pdf = re.search(r'<meta name=[\"\']citation_pdf_url[\"\'] content=[\"\']([^\"\']+)[\"\']', html)
                if m_pdf and (m_pdf.group(1).lower().endswith(".pdf") or "nvlpubs.nist.gov" in m_pdf.group(1)):
                    pdf_url = m_pdf.group(1)

            # 3. Check any direct nvlpubs PDF link in the document section
            if not pdf_url:
                m_nvl = re.search(r'href=[\"\'](https?://nvlpubs\.nist\.gov/[^\"\']+\.pdf)[\"\']', html)
                if m_nvl:
                    pdf_url = m_nvl.group(1)

            # 4. Check pub-doi-link fallback
            if not pdf_url:
                m_doi = re.search(r'id=[\"\']pub-doi-link[\"\'][^>]*href=[\"\']([^\"\']+)[\"\']', html)
                if m_doi and "doi.org/10.6028" in m_doi.group(1):
                    pdf_url = m_doi.group(1)

            # Extract abstract/description
            desc = ""
            m_desc = re.search(r'<meta (?:name|property)=[\"\'](?:description|og:description)[\"\'] content=[\"\'](.*?)[\"\']', html)
            if m_desc:
                desc = m_desc.group(1).strip()

            return True, normalize_pdf_url(pdf_url), desc
        except Exception:
            if attempt < max_retries:
                time.sleep(min(1.5 * (2 ** (attempt - 1)), 12))
                continue
            return False, None, ""
    return False, None, ""


def process_record(record, prev_by_url):
    """Worker task to resolve direct PDF URL for a record, preserving cache on transient failures."""
    fetch_ok, pdf_url, desc = extract_pdf_from_detail(record["detail_url"])
    if not fetch_ok:
        prev = prev_by_url.get(record["detail_url"])
        if prev:
            record["pdf_url"] = normalize_pdf_url(prev.get("pdf_url"))
            record["description"] = prev.get("description", "")
            return record, False
    record["pdf_url"] = pdf_url
    record["description"] = desc
    return record, fetch_ok


def format_lastmod(date_str, fallback_today):
    """Formats CSRC publication date (e.g. M/D/YYYY) to ISO YYYY-MM-DD for zero-churn sitemaps."""
    if date_str:
        try:
            dt = datetime.strptime(date_str, "%m/%d/%Y")
            return dt.strftime("%Y-%m-%d")
        except Exception:
            pass
    return fallback_today


def write_if_changed(output_path, content):
    """Write text file only when bytes differ to avoid unnecessary mtime/git churn."""
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                if f.read() == content:
                    return False
        except Exception:
            pass
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return True


def generate_sitemap_xml(docs, output_path):
    """Generates a compliant flat <urlset> XML sitemap."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    urlset = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

    for doc in docs:
        if not doc.get("pdf_url"):
            continue
        url_elem = ET.SubElement(urlset, "url")
        loc_elem = ET.SubElement(url_elem, "loc")
        loc_elem.text = doc["pdf_url"]

        lastmod_elem = ET.SubElement(url_elem, "lastmod")
        lastmod_elem.text = format_lastmod(doc.get("date"), today)

        freq_elem = ET.SubElement(url_elem, "changefreq")
        freq_elem.text = "weekly"

        prio_elem = ET.SubElement(url_elem, "priority")
        prio_elem.text = "1.0"

    xml_str = ET.tostring(urlset, encoding="utf-8")
    parsed = minidom.parseString(xml_str)
    pretty_xml = parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")

    write_if_changed(output_path, pretty_xml)


def main():
    start_time = time.time()
    print("=" * 65)
    print(" NIST Cybersecurity & Computing Standards Sitemap Generator")
    print("=" * 65)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    catalog_path = os.path.join(script_dir, "nist_catalog.json")

    # Load previous catalog to protect against transient CSRC HTTP failures
    prev_catalog = {}
    prev_by_url = {}
    if os.path.exists(catalog_path):
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                prev_catalog = json.load(f)
            for doc in prev_catalog.get("documents", []):
                du = doc.get("detail_url")
                if du:
                    prev_by_url[du] = doc
        except Exception as e:
            print(f"Warning: could not read previous catalog ({e})")

    # 1. Inspect first search page to determine total records
    print("Connecting to NIST CSRC publications database...")
    page1_html = fetch_search_page(1, ipp=100)

    m_tot = re.search(r'data-total-records=[\"\'](\d+)[\"\']', page1_html)
    total_records = int(m_tot.group(1)) if m_tot else 1500
    total_pages = (total_records + 99) // 100
    print(f"Discovered {total_records} standards across {total_pages} search pages.")

    # 2. Fetch all search pages in parallel (fail fast if any page fails after retries)
    raw_by_url = {}
    for rec in parse_search_records(page1_html):
        raw_by_url[rec["detail_url"]] = rec

    if total_pages > 1:
        print(f"Fetching remaining {total_pages - 1} search catalog pages in parallel...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(fetch_search_page, p, 100): p for p in range(2, total_pages + 1)}
            for f in concurrent.futures.as_completed(futures):
                p_html = f.result()
                for rec in parse_search_records(p_html):
                    raw_by_url[rec["detail_url"]] = rec

    all_raw_records = list(raw_by_url.values())
    print(f"Total unique publication records indexed from CSRC: {len(all_raw_records)}")
    if len(all_raw_records) < int(total_records * 0.95):
        print(f"ERROR: Only indexed {len(all_raw_records)}/{total_records} records. Aborting to prevent partial sitemap.")
        sys.exit(1)

    # 3. Concurrently resolve direct PDF download URLs with retries & transient-failure fallback
    print(f"Resolving direct PDF download links across {MAX_WORKERS} worker threads...")
    resolved_records = []
    transient_failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(process_record, r, prev_by_url): r for r in all_raw_records}
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res, ok = f.result()
            if not ok:
                transient_failures += 1
            if res:
                resolved_records.append(res)
            completed += 1
            if completed % 250 == 0 or completed == len(all_raw_records):
                print(f"  Processed {completed}/{len(all_raw_records)} publications (transient fallbacks: {transient_failures})...")

    # Deterministically sort resolved records by series, number, detail_url, and PDF URL for zero-churn diffs
    resolved_records.sort(
        key=lambda r: (
            r.get("series", "").upper(),
            r.get("number", "").upper(),
            r.get("detail_url", ""),
            r.get("pdf_url") or "",
        )
    )

    # Filter records with valid PDFs
    docs_with_pdf = [r for r in resolved_records if r.get("pdf_url")]
    final_docs = [r for r in docs_with_pdf if r.get("status", "").lower() == "final"]
    all_docs = docs_with_pdf

    print(f"\nPDF Resolution Results:")
    print(f"  Final Approved Standards with direct PDF: {len(final_docs)}")
    print(f"  Total Standards (Final + Active Drafts) with PDF: {len(all_docs)}")
    print(f"  Transient detail-page fetch fallbacks used: {transient_failures}")

    # Safety Guard
    if len(final_docs) < 200:
        print(f"ERROR: Only {len(final_docs)} final standards resolved. Threshold is 200.")
        print("Aborting to preserve existing valid sitemap files.")
        sys.exit(1)

    # 4. Generate Sitemaps & Outputs
    final_sitemap_path = os.path.join(script_dir, "nist_standards_final.xml")
    generate_sitemap_xml(final_docs, final_sitemap_path)
    print(f"Generated: {final_sitemap_path} ({len(final_docs)} URLs)")

    all_sitemap_path = os.path.join(script_dir, "nist_standards_all.xml")
    generate_sitemap_xml(all_docs, all_sitemap_path)
    print(f"Generated: {all_sitemap_path} ({len(all_docs)} URLs)")

    urls_path = os.path.join(script_dir, "nist_pdf_urls.txt")
    write_if_changed(urls_path, "".join(f"{d['pdf_url']}\n" for d in final_docs))
    print(f"Generated: {urls_path}")

    # Full Catalog Metadata (preserve generated_at when content is unchanged)
    existing_generated_at = None
    if (
        prev_catalog.get("total_final_standards") == len(final_docs)
        and prev_catalog.get("total_all_standards") == len(all_docs)
        and prev_catalog.get("documents") == resolved_records
    ):
        existing_generated_at = prev_catalog.get("generated_at")

    generated_at_str = existing_generated_at or datetime.now(timezone.utc).isoformat()
    catalog_json_str = json.dumps({
        "generated_at": generated_at_str,
        "total_final_standards": len(final_docs),
        "total_all_standards": len(all_docs),
        "documents": resolved_records
    }, indent=2) + "\n"

    write_if_changed(catalog_path, catalog_json_str)
    print(f"Generated: {catalog_path}")

    elapsed = time.time() - start_time
    print(f"All done in {elapsed:.2f} seconds!")


if __name__ == "__main__":
    main()
