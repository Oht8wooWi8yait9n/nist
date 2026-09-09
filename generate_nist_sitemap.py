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
import requests
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime, timezone
import concurrent.futures

BASE_URL = "https://csrc.nist.gov"
SEARCH_URL = f"{BASE_URL}/publications/search"

SERIES_FILTERS = ["FIPS", "SP", "IR", "CSWP", "AI"]
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
}


def fetch_search_page(page_num, ipp=100):
    """Fetches a single search result page from CSRC."""
    params = [("ipp-lg", str(ipp)), ("page", str(page_num))]
    for s in SERIES_FILTERS:
        params.append(("series-lg", s))

    url = f"{SEARCH_URL}?" + "&".join(f"{k}={v}" for k, v in params)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        print(f"Error fetching search page {page_num}: {e}")
    return ""


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


def extract_pdf_from_detail(detail_url):
    """Fetches publication detail page and extracts direct PDF / DOI URL."""
    try:
        r = requests.get(detail_url, headers=HEADERS, timeout=12)
        if r.status_code != 200:
            return None, ""
        
        html = r.text
        pdf_url = None
        
        # 1. Check local download link
        m_local = re.search(r'id=[\"\']pub-local-download-link[\"\'][^>]*href=[\"\']([^\"\']+)[\"\']', html)
        if not m_local:
            m_local = re.search(r'href=[\"\']([^\"\']+\.pdf)[\"\'][^>]*id=[\"\']pub-local-download-link[\"\']', html)
        if m_local and (m_local.group(1).endswith(".pdf") or "nvlpubs.nist.gov" in m_local.group(1)):
            pdf_url = m_local.group(1)

        # 2. Check citation_pdf_url meta tag
        if not pdf_url:
            m_pdf = re.search(r'<meta name=[\"\']citation_pdf_url[\"\'] content=[\"\']([^\"\']+)[\"\']', html)
            if m_pdf and (m_pdf.group(1).endswith(".pdf") or "nvlpubs.nist.gov" in m_pdf.group(1)):
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

        return pdf_url, desc
    except Exception:
        return None, ""


def process_record(record):
    """Worker task to resolve direct PDF URL for a record."""
    pdf_url, desc = extract_pdf_from_detail(record["detail_url"])
    record["pdf_url"] = pdf_url
    record["description"] = desc
    return record


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
        lastmod_elem.text = today

        freq_elem = ET.SubElement(url_elem, "changefreq")
        freq_elem.text = "weekly"

        prio_elem = ET.SubElement(url_elem, "priority")
        prio_elem.text = "1.0"

    xml_str = ET.tostring(urlset, encoding="utf-8")
    parsed = minidom.parseString(xml_str)
    pretty_xml = parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(pretty_xml)


def main():
    start_time = time.time()
    print("=" * 65)
    print(" NIST Cybersecurity & Computing Standards Sitemap Generator")
    print("=" * 65)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Inspect first search page to determine total records
    print("Connecting to NIST CSRC publications database...")
    page1_html = fetch_search_page(1, ipp=100)
    if not page1_html:
        print("ERROR: Failed to connect to CSRC. Aborting.")
        sys.exit(1)

    m_tot = re.search(r'data-total-records=[\"\'](\d+)[\"\']', page1_html)
    total_records = int(m_tot.group(1)) if m_tot else 1500
    total_pages = (total_records + 99) // 100
    print(f"Discovered {total_records} standards across {total_pages} search pages.")

    # 2. Fetch all search pages in parallel
    all_raw_records = []
    all_raw_records.extend(parse_search_records(page1_html))

    if total_pages > 1:
        print(f"Fetching remaining {total_pages - 1} search catalog pages in parallel...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futures = {ex.submit(fetch_search_page, p, 100): p for p in range(2, total_pages + 1)}
            for f in concurrent.futures.as_completed(futures):
                p_html = f.result()
                if p_html:
                    all_raw_records.extend(parse_search_records(p_html))

    print(f"Total publication records indexed from CSRC: {len(all_raw_records)}")

    # 3. Concurrently resolve direct PDF download URLs
    print(f"Resolving direct PDF download links across 16 worker threads...")
    resolved_records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futures = {ex.submit(process_record, r): r for r in all_raw_records}
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                resolved_records.append(res)
            completed += 1
            if completed % 250 == 0 or completed == len(all_raw_records):
                print(f"  Processed {completed}/{len(all_raw_records)} publications...")

    # Filter records with valid PDFs
    docs_with_pdf = [r for r in resolved_records if r.get("pdf_url")]
    final_docs = [r for r in docs_with_pdf if r.get("status", "").lower() == "final"]
    all_docs = docs_with_pdf

    print(f"\nPDF Resolution Results:")
    print(f"  Final Approved Standards with direct PDF: {len(final_docs)}")
    print(f"  Total Standards (Final + Active Drafts) with PDF: {len(all_docs)}")

    # Safety Guard
    if len(final_docs) < 200:
        print(f"ERROR: Only {len(final_docs)} final standards resolved. Threshold is 200.")
        print("Aborting to preserve existing valid sitemap files.")
        sys.exit(1)

    # 4. Generate Sitemaps & Outputs
    # A. Final Standards Sitemap (Primary)
    final_sitemap_path = os.path.join(script_dir, "nist_standards_final.xml")
    generate_sitemap_xml(final_docs, final_sitemap_path)
    print(f"Generated: {final_sitemap_path} ({len(final_docs)} URLs)")

    # B. All Standards + Drafts Sitemap (Extended)
    all_sitemap_path = os.path.join(script_dir, "nist_standards_all.xml")
    generate_sitemap_xml(all_docs, all_sitemap_path)
    print(f"Generated: {all_sitemap_path} ({len(all_docs)} URLs)")

    # C. Plain Text URLs
    urls_path = os.path.join(script_dir, "nist_pdf_urls.txt")
    with open(urls_path, "w", encoding="utf-8") as f:
        for d in final_docs:
            f.write(f"{d['pdf_url']}\n")
    print(f"Generated: {urls_path}")

    # D. Full Catalog Metadata
    catalog_path = os.path.join(script_dir, "nist_catalog.json")
    with open(catalog_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_final_standards": len(final_docs),
            "total_all_standards": len(all_docs),
            "documents": resolved_records
        }, f, indent=2)
    print(f"Generated: {catalog_path}")

    elapsed = time.time() - start_time
    print(f"All done in {elapsed:.2f} seconds!")


if __name__ == "__main__":
    main()
