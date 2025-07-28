#!/usr/bin/env python3
"""
HTTP client wrapper with proxy support, retry logic, and user agent rotation
Handles all HTTP operations for the scanner
"""

import asyncio
import aiohttp
import ssl
import random
import time
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse
import socket

from .utils import random_user_agent, print_status

class HTTPClient:
    """Async HTTP client with advanced features"""
    
    def __init__(self, timeout: int = 10, max_retries: int = 3, 
                 proxy: Optional[str] = None, verify_ssl: bool = False):
        self.timeout = timeout
        self.max_retries = max_retries
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.session = None
        
        # SSL context for bypassing certificate verification
        self.ssl_context = ssl.create_default_context()
        if not verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            ssl=self.ssl_context,
            limit=1000,
            limit_per_host=100,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            trust_env=True
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Generate headers with random user agent"""
        headers = {
            'User-Agent': random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    async def get(self, url: str, headers: Optional[Dict[str, str]] = None, 
                  follow_redirects: bool = True) -> Tuple[int, str, Dict[str, str]]:
        """
        Perform GET request with retry logic
        Returns: (status_code, content, headers)
        """
        request_headers = self._get_headers(headers)
        
        for attempt in range(self.max_retries):
            try:
                async with self.session.get(
                    url, 
                    headers=request_headers,
                    proxy=self.proxy,
                    allow_redirects=follow_redirects,
                    ssl=self.ssl_context
                ) as response:
                    content = await response.text()
                    return response.status, content, dict(response.headers)
                    
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return 0, "", {}
                await asyncio.sleep(random.uniform(1, 3))
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return 0, "", {}
                await asyncio.sleep(random.uniform(1, 3))
        
        return 0, "", {}
    
    async def post(self, url: str, data: Optional[Dict] = None, 
                   headers: Optional[Dict[str, str]] = None) -> Tuple[int, str, Dict[str, str]]:
        """
        Perform POST request with retry logic
        Returns: (status_code, content, headers)
        """
        request_headers = self._get_headers(headers)
        
        for attempt in range(self.max_retries):
            try:
                async with self.session.post(
                    url,
                    data=data,
                    headers=request_headers,
                    proxy=self.proxy,
                    ssl=self.ssl_context
                ) as response:
                    content = await response.text()
                    return response.status, content, dict(response.headers)
                    
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return 0, "", {}
                await asyncio.sleep(random.uniform(1, 3))
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return 0, "", {}
                await asyncio.sleep(random.uniform(1, 3))
        
        return 0, "", {}
    
    async def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str]]:
        """
        Perform HEAD request to check if resource exists
        Returns: (status_code, headers)
        """
        request_headers = self._get_headers(headers)
        
        try:
            async with self.session.head(
                url,
                headers=request_headers,
                proxy=self.proxy,
                ssl=self.ssl_context,
                allow_redirects=False
            ) as response:
                return response.status, dict(response.headers)
        except:
            return 0, {}

class HTTPScanner:
    """High-level HTTP scanner for vulnerability detection"""
    
    def __init__(self, timeout: int = 10, max_retries: int = 3, 
                 proxy: Optional[str] = None, verify_ssl: bool = False):
        self.timeout = timeout
        self.max_retries = max_retries
        self.proxy = proxy
        self.verify_ssl = verify_ssl
    
    async def scan_url(self, base_url: str, path: str) -> Dict[str, Any]:
        """
        Scan a specific URL path for vulnerabilities
        Returns: Dictionary with scan results
        """
        url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
        
        async with HTTPClient(
            timeout=self.timeout,
            max_retries=self.max_retries,
            proxy=self.proxy,
            verify_ssl=self.verify_ssl
        ) as client:
            status, content, headers = await client.get(url)
            
            result = {
                'url': url,
                'path': path,
                'status_code': status,
                'content_length': len(content) if content else 0,
                'headers': headers,
                'content': content[:1000] if content else "",  # Limit content for memory
                'vulnerable': False,
                'vulnerability_type': None,
                'extracted_data': {}
            }
            
            # Analyze response for vulnerabilities
            if status == 200 and content:
                result['vulnerable'], result['vulnerability_type'], result['extracted_data'] = \
                    self._analyze_response(path, content, headers)
            
            return result
    
    def _analyze_response(self, path: str, content: str, headers: Dict[str, str]) -> Tuple[bool, Optional[str], Dict]:
        """
        Analyze HTTP response for Laravel vulnerabilities
        Returns: (is_vulnerable, vulnerability_type, extracted_data)
        """
        extracted_data = {}
        
        # Check for .env file exposure
        if path.endswith('.env') or '.env' in path:
            if self._is_env_file(content):
                from .utils import parse_env_file, extract_secrets_from_text
                env_vars = parse_env_file(content)
                secrets = extract_secrets_from_text(content)
                extracted_data = {
                    'env_vars': env_vars,
                    'secrets': secrets
                }
                return True, 'env_exposed', extracted_data
        
        # Check for PHPUnit eval-stdin vulnerability
        if 'eval-stdin.php' in path:
            if 'PHPUnit' in content or 'eval(' in content:
                return True, 'phpunit_eval', extracted_data
        
        # Check for Ignition RCE vulnerability
        if '_ignition' in path:
            if 'ignition' in content.lower() or 'solution' in content.lower():
                from .utils import extract_secrets_from_text
                secrets = extract_secrets_from_text(content)
                if secrets:
                    extracted_data['secrets'] = secrets
                return True, 'ignition_rce', extracted_data
        
        # Check for Telescope exposure
        if 'telescope' in path:
            if 'telescope' in content.lower() or 'laravel' in content.lower():
                return True, 'telescope_exposed', extracted_data
        
        # Check for log file exposure
        if 'log' in path and ('.log' in path or 'logs' in path):
            if self._is_log_file(content):
                from .utils import extract_secrets_from_text
                secrets = extract_secrets_from_text(content)
                if secrets:
                    extracted_data['secrets'] = secrets
                return True, 'log_exposed', extracted_data
        
        # Check for config file exposure
        if 'config' in path and ('.php' in path or '.json' in path):
            from .utils import extract_secrets_from_text
            secrets = extract_secrets_from_text(content)
            if secrets:
                extracted_data['secrets'] = secrets
                return True, 'config_exposed', extracted_data
        
        # Check for debug information
        if any(debug_indicator in content.lower() for debug_indicator in 
               ['whoops', 'debugbar', 'debug', 'stack trace', 'exception']):
            from .utils import extract_secrets_from_text
            secrets = extract_secrets_from_text(content)
            if secrets:
                extracted_data['secrets'] = secrets
            return True, 'debug_exposed', extracted_data
        
        return False, None, extracted_data
    
    def _is_env_file(self, content: str) -> bool:
        """Check if content appears to be a .env file"""
        env_indicators = ['APP_KEY=', 'DB_PASSWORD=', 'MAIL_PASSWORD=', 'APP_ENV=']
        return any(indicator in content for indicator in env_indicators)
    
    def _is_log_file(self, content: str) -> bool:
        """Check if content appears to be a log file"""
        log_indicators = ['[20', '] local.', '] production.', 'ERROR', 'INFO', 'DEBUG']
        return any(indicator in content for indicator in log_indicators)

async def test_connection(url: str, timeout: int = 5) -> bool:
    """Test if URL is accessible"""
    try:
        async with HTTPClient(timeout=timeout, verify_ssl=False) as client:
            status, _, _ = await client.head(url)
            return status > 0
    except:
        return False

def parse_proxy(proxy_string: str) -> Optional[str]:
    """Parse proxy string into proper format"""
    if not proxy_string:
        return None
    
    if '://' not in proxy_string:
        proxy_string = f"http://{proxy_string}"
    
    return proxy_string

def get_base_url(url: str) -> str:
    """Extract base URL from full URL"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def is_valid_target(target: str) -> bool:
    """Validate if target is a valid URL or IP"""
    from .utils import validate_ip, validate_url
    
    # Check if it's a valid IP
    if validate_ip(target):
        return True
    
    # Check if it's a valid URL
    if validate_url(target):
        return True
    
    # Check if it's a domain/hostname
    try:
        socket.gethostbyname(target)
        return True
    except:
        return False