import requests
import re
import concurrent.futures
from urllib.parse import urlparse, urljoin
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from core.display import print_status
except ImportError:
    def print_status(msg, type="info"):
        print(f"[{type.upper()}] {msg}")

class MorandaCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Android 10; Mobile; rv:109.0) Gecko/115.0 Firefox/115.0 MorandaHunter/1.0'
        })
        
        # [SAFETY BRAKES] Termux Crash Se Bachne Ke Liye
        self.max_pages = 50        # Sirf 50 pages scan honge
        self.max_threads = 10      # Threads controlled rahenge
        
        self.visited = set()
        self.internal_links = set()
        self.juicy_links = set()
        
        # Files to Ignore
        self.ignore_ext = ['.png', '.jpg', '.jpeg', '.gif', '.css', '.svg', '.ico', '.woff', '.ttf', '.pdf', '.mp4']

        # [UPGRADE 1] Expanded Juicy Parameters
        self.juicy_params = [
            'redirect', 'url', 'path', 'file', 'source', 'u', 'r', 'return', 'next',
            'id', 'user', 'account', 'admin', 'debug', 'role', 'cmd', 'exec', 'query'
        ]

        # [UPGRADE 2] Fixed Sensitive Comments Regex
        # (TODO, FIXME, API Keys, Passwords dhoondne ke liye)
        self.sensitive_comments = re.compile(r'(TODO|FIXME|BUG|XXX|NOTE|HACK|apikey|password|secret)', re.IGNORECASE)

    def is_juicy(self, url):
        """Check for dangerous parameters"""
        for param in self.juicy_params:
            if f"{param}=" in url or f"{param}&" in url:
                return True
        return False

    def extract_from_html(self, html, base_url):
        """
        [UPGRADE 3] Advanced Regex Extraction
        Href, Src, Action, Data-Url sab nikaalega.
        """
        extracted = set()
        
        # Powerful Regex Patterns
        patterns = [
            r'href=["\'](.*?)["\']',
            r'src=["\'](.*?)["\']',
            r'action=["\'](.*?)["\']',
            r'data-url=["\'](.*?)["\']'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html)
            for link in matches:
                link = link.strip()
                if not link or link.startswith('#') or link.startswith('javascript:') or link.startswith('mailto:'):
                    continue
                
                # Check extensions
                if any(link.lower().endswith(ext) for ext in self.ignore_ext):
                    continue

                full_url = urljoin(base_url, link)
                extracted.add(full_url)

        return extracted

    def find_comments(self, html):
        """Developer ki galtiyan dhoondho"""
        # HTML Comments comments = re.findall(r'', html, re.DOTALL)
        findings = []
        for comment in comments:
            if self.sensitive_comments.search(comment):
                clean_comment = comment.strip()[:50] # Shorten it
                findings.append(clean_comment)
        return findings

    def crawl_page(self, url):
        """Single Page Processor"""
        # Safety Check: Limit cross ho gayi to ruk jao
        if url in self.visited or len(self.visited) >= self.max_pages:
            return set(), []

        try:
            res = self.session.get(url, timeout=5, verify=False)
            self.visited.add(url)
            
            # 1. Juicy Check
            if self.is_juicy(url):
                self.juicy_links.add(url)

            # 2. Extract Links
            links = self.extract_from_html(res.text, url)
            
            # 3. Extract Comments
            comments = self.find_comments(res.text)
            if comments:
                print_status(f"📝 Found sensitive comments in {url}: {comments}", "info")

            return links, comments
            
        except:
            return set(), []

    def crawl(self, start_url):
        print_status(f"🕷️ Spider started on {start_url} (Safe Mode: Max {self.max_pages} pages)...", "info")
        
        domain = urlparse(start_url).netloc
        queue = {start_url}
        
        # Threaded Crawling
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # First batch
            future_to_url = {executor.submit(self.crawl_page, url): url for url in queue}
            
            while future_to_url and len(self.visited) < self.max_pages:
                # Process completed futures
                done, not_done = concurrent.futures.wait(future_to_url, timeout=2, return_when=concurrent.futures.FIRST_COMPLETED)
                
                # Nayi links ke liye temporary holder
                next_batch = set()
                
                for future in done:
                    url = future_to_url.pop(future)
                    try:
                        links, comments = future.result()
                        for l in links:
                            if domain in l and l not in self.visited:
                                self.internal_links.add(l)
                                next_batch.add(l)
                    except: pass
                
                # Add new links to execution queue (if limit not reached)
                for l in list(next_batch)[:10]: # Batch size limit
                    if len(self.visited) < self.max_pages:
                        future_to_url[executor.submit(self.crawl_page, l)] = l
                    else:
                        break

        print_status(f"🕸️ Spider extracted {len(self.internal_links)} internal endpoints.", "success")
        
        if self.juicy_links:
            print_status(f"💰 Found {len(self.juicy_links)} JUICY parameters (Attack Surface)!", "critical")

        return list(self.internal_links), list(self.juicy_links)
