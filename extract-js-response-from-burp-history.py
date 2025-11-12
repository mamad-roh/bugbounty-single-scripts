#!/usr/bin/env python3
"""
extract_js_responses_strip_headers.py

Usage:
    python3 extract-js-response-from-burp-history.py <burp-xml-file> <output-dir>

Extract <response> elements that belong to .js resources from a Burp XML
export, strip HTTP response headers (status line + headers) and save only
the response body to separate .js files.

Behavior:
 - Detects JS items by:
     * <extension>js</extension>
     * or path/url that ends with ".js" (case-insensitive)
 - If <response> has attribute base64="true" it base64-decodes the content.
 - Finds the first CRLF-CRLF (\\r\\n\\r\\n) or LF-LF (\\n\\n) and treats
   everything after it as the body.
 - Writes files in binary mode to preserve exact bytes.
 - Produces safe filenames and avoids overwriting by adding suffixes.
"""

import sys
import os
import re
import base64
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

def safe_name(s):
    s = re.sub(r'[:/\\?&=#]+', '_', s)
    s = re.sub(r'[^A-Za-z0-9_.\-]', '_', s)
    s = re.sub(r'_{2,}', '_', s)
    return s.strip('_') or 'file'

def is_js_item(item):
    ext = (item.findtext('extension') or '').strip().lower()
    path = (item.findtext('path') or '').strip().lower()
    url = (item.findtext('url') or '').strip().lower()
    if ext == 'js':
        return True
    if path.endswith('.js') or url.endswith('.js'):
        return True
    return False

def strip_http_headers(raw_bytes):
    """
    Given bytes (possibly starting with an HTTP status line + headers),
    return the bytes representing the body (i.e., data after the first
    blank line).
    """
    if not raw_bytes:
        return raw_bytes
    # try CRLF CRLF first (most common)
    sep = b'\r\n\r\n'
    idx = raw_bytes.find(sep)
    if idx != -1:
        return raw_bytes[idx + len(sep):]
    # fallback to LF LF
    sep2 = b'\n\n'
    idx2 = raw_bytes.find(sep2)
    if idx2 != -1:
        return raw_bytes[idx2 + len(sep2):]
    # no headers found — return as-is
    return raw_bytes

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 extract_js_responses_strip_headers.py <burp-xml-file> <output-dir>")
        sys.exit(1)

    xml_path = sys.argv[1]
    out_dir = sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    try:
        tree = ET.parse(xml_path)
    except Exception as e:
        print(f"Error parsing XML: {e}")
        sys.exit(2)
    root = tree.getroot()

    seen = {}
    count = 0

    for item in root.findall('.//item'):
        if not is_js_item(item):
            continue

        resp_el = item.find('response')
        if resp_el is None:
            continue

        raw = resp_el.text or ''
        is_b64 = (resp_el.get('base64') or 'false').lower() == 'true'

        try:
            if is_b64:
                raw_bytes = base64.b64decode(raw)
            else:
                # keep as utf-8 bytes (replace errors)
                raw_bytes = (raw).encode('utf-8', errors='replace')
        except Exception:
            # fallback: write raw text bytes
            raw_bytes = (raw).encode('utf-8', errors='replace')

        # strip HTTP headers if present
        body_bytes = strip_http_headers(raw_bytes)

        url = item.findtext('url') or ''
        host = (item.findtext('host') or '').strip()
        path = (item.findtext('path') or '').strip()

        # build filename base: prefer host+path from URL if available
        try:
            parsed = urlparse(url) if url else None
            if parsed and parsed.path:
                fname_base = f"{parsed.netloc}{parsed.path}"
            else:
                fname_base = f"{host}{path}"
        except Exception:
            fname_base = f"{host}{path}"

        fname_base = safe_name(fname_base)
        # Ensure extension .js for easy identification
        if not fname_base.lower().endswith('.js'):
            fname = fname_base + ".js"
        else:
            fname = fname_base

        # avoid overwrite
        if fname in seen:
            seen[fname] += 1
            name, ext = os.path.splitext(fname)
            fname = f"{name}_{seen[fname]}{ext}"
        else:
            seen[fname] = 0

        out_path = os.path.join(out_dir, fname)
        try:
            with open(out_path, 'wb') as f:
                f.write(body_bytes)
            count += 1
        except Exception as e:
            print(f"Failed to write {out_path}: {e}")

    print(f"Done. Extracted {count} JS responses (headers stripped) into: {os.path.abspath(out_dir)}")

if __name__ == "__main__":
    main()

