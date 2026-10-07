import os
import re
import requests
import tempfile
import urllib.parse
from markitdown import MarkItDown
from backend.db import db
from backend.misp_galaxy import enricher
from pypdf import PdfReader

REPO_URL = "https://raw.githubusercontent.com/jacobdjwilson/awesome-annual-security-reports/main/README.md"

def fetch_report_links():
    print("Fetching README from awesome-annual-security-reports...")
    resp = requests.get(REPO_URL)
    resp.raise_for_status()
    readme = resp.text
    
    pdf_links = re.findall(r'\[.*?\]\((https?://[^\)]+\.pdf)\)', readme)
    return list(set(pdf_links))

def download_pdf(url):
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        
        fd, path = tempfile.mkstemp(suffix=".pdf")
        with os.fdopen(fd, 'wb') as f:
            f.write(resp.content)
        return path
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return None

def verify_all_reports():
    pdf_links = fetch_report_links()
    if not pdf_links:
        print("No PDF links found in README.")
        return

    print(f"Found {len(pdf_links)} PDF reports to analyze!")
    
    enricher.initialize()
    
    print("Querying MongoDB for distinct threats across all sources...")
    # 1. MISP Galaxy Clusters
    misp_clusters = db.events.distinct("galaxy_clusters")
    # 2. ThreatFox Malware Families
    tf_malware = db.indicators.distinct("malware_printable", {"source": "ThreatFox"})
    # 3. MalwareBazaar Signatures
    mb_signatures = db.malware.distinct("signature")
    
    # Combine all unique threat names (ignoring None or empty strings)
    all_threats = set(misp_clusters + tf_malware + mb_signatures)
    all_threats = {t for t in all_threats if t and len(t) > 2} # filter out junk/empty
    
    print(f"Found {len(all_threats)} distinct threat names (MISP + ThreatFox + MalwareBazaar) in our DB.")
    
    md = MarkItDown()

    
    # We will build a brand new collection just for the UI you showed me!
    reports_to_insert = []
    
    for i, url in enumerate(pdf_links, 1):
        filename = urllib.parse.unquote(url.split('/')[-1])
        print(f"\n[{i}/{len(pdf_links)}] Processing {filename}...")
        
        pdf_path = download_pdf(url)
        if not pdf_path:
            continue
            
        try:
            # Get Page Count
            reader = PdfReader(pdf_path)
            num_pages = len(reader.pages)
            
            # Convert to Markdown
            result = md.convert(pdf_path)
            text_content = result.text_content
            text_lower = text_content.lower()
            
            # Verify Threats
            verified_in_this_report = []
            for cluster in all_threats:
                if cluster.lower() in text_lower:
                    verified_in_this_report.append(cluster)
            
            print(f" -> Found {num_pages} pages, verified {len(verified_in_this_report)} threats.")
            
            # Extract Year from URL or filename
            year_match = re.search(r'(20\d{2})', filename)
            year = year_match.group(1) if year_match else "2024"
            
            # Extract Vendor (First word of filename usually)
            vendor = filename.split()[0].replace('.pdf', '').replace('_', '').replace('-', '')
            
            # Build the Document for the UI
            report_doc = {
                "document_name": filename.replace('.pdf', ''),
                "vendor": vendor,
                "year": year,
                "pages": num_pages,
                "passages": len(text_content.split('\n\n')), # Rough estimate of passages
                "threats_named": len(verified_in_this_report),
                "verified_threats_list": verified_in_this_report,
                "pdf_url": url,
                "markdown_content": text_content
            }
            
            reports_to_insert.append(report_doc)
            
        except Exception as e:
            print(f" -> Failed to process PDF: {e}")
            
        finally:
            if os.path.exists(pdf_path):
                os.remove(pdf_path)

    # Insert into the database for the frontend to consume
    if reports_to_insert:
        print(f"\nInserting {len(reports_to_insert)} structured reports into the database...")
        # Drop old collection if exists to avoid duplicates during testing
        db.annual_reports.drop()
        db.annual_reports.insert_many(reports_to_insert)
        
    print("\n" + "="*50)
    print("FINAL VERIFICATION SUMMARY")
    print("="*50)
    print(f"Total Reports Analyzed: {len(reports_to_insert)}")
    print("="*50)

if __name__ == "__main__":
    verify_all_reports()
