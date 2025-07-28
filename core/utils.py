#!/usr/bin/env python3
"""
Utility functions and helpers for Cracker Scanner 2025
Includes regex patterns, formatting, encoding, and helper functions
"""

import re
import json
import base64
import urllib.parse
from typing import Dict, List, Optional, Union, Any
import ipaddress
import random
import string

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Laravel vulnerability patterns
LARAVEL_PATTERNS = {
    'env_exposed': [
        r'APP_KEY=base64:([A-Za-z0-9+/=]+)',
        r'DB_PASSWORD=([^\s\n]+)',
        r'DB_USERNAME=([^\s\n]+)',
        r'MAIL_PASSWORD=([^\s\n]+)',
        r'AWS_SECRET_ACCESS_KEY=([^\s\n]+)',
        r'MAIL_MAILERS_SMTP_PASSWORD=([^\s\n]+)'
    ],
    'smtp_credentials': [
        r'MAIL_HOST=([^\s\n]+)',
        r'MAIL_PORT=([^\s\n]+)',
        r'MAIL_USERNAME=([^\s\n]+)',
        r'MAIL_PASSWORD=([^\s\n]+)',
        r'MAIL_FROM_ADDRESS=([^\s\n]+)'
    ],
    'aws_credentials': [
        r'AWS_ACCESS_KEY_ID=([^\s\n]+)',
        r'AWS_SECRET_ACCESS_KEY=([^\s\n]+)',
        r'AWS_DEFAULT_REGION=([^\s\n]+)',
        r'AWS_BUCKET=([^\s\n]+)'
    ],
    'api_keys': [
        r'SENDGRID_API_KEY=([^\s\n]+)',
        r'MAILGUN_DOMAIN=([^\s\n]+)',
        r'MAILGUN_SECRET=([^\s\n]+)',
        r'TWILIO_SID=([^\s\n]+)',
        r'TWILIO_TOKEN=([^\s\n]+)',
        r'STRIPE_KEY=([^\s\n]+)',
        r'STRIPE_SECRET=([^\s\n]+)'
    ],
    'database_urls': [
        r'DATABASE_URL=([^\s\n]+)',
        r'REDIS_URL=([^\s\n]+)',
        r'MONGODB_URI=([^\s\n]+)'
    ],
    'ignition_debug': [
        r'"message":\s*"(.+?)"',
        r'"file":\s*"(.+?)"',
        r'"line":\s*(\d+)',
        r'"stack":\s*\[(.+?)\]'
    ]
}

# Common vulnerable Laravel paths (subset of 2500+)
VULNERABLE_PATHS = [
    '.env',
    '.env.backup',
    '.env.example',
    '.env.local',
    '.env.production',
    '.env.staging',
    '.env.dev',
    '.env.old',
    'phpunit.xml',
    'vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    '_ignition/execute-solution',
    '_ignition/health-check',
    'telescope/requests',
    'horizon/api/jobs',
    'storage/logs/laravel.log',
    'bootstrap/cache/config.php',
    'config/app.php',
    'config/database.php',
    'config/mail.php',
    'storage/framework/cache',
    'storage/framework/sessions',
    'storage/app/public',
    'public/storage',
    'artisan',
    'composer.json',
    'composer.lock',
    'package.json',
    'webpack.mix.js',
    'routes/web.php',
    'routes/api.php',
    'app/Http/Controllers',
    'resources/views',
    'database/migrations',
    'database/seeds',
    'public/js/app.js',
    'public/css/app.css',
    'public/mix-manifest.json',
    'storage/debugbar',
    'debug/vars',
    'debug/pprof',
    '_debugbar/open',
    'clockwork/app',
    'barryvdh/laravel-debugbar',
    'filp/whoops'
]

def extract_secrets_from_text(text: str) -> Dict[str, List[str]]:
    """Extract secrets from text using regex patterns"""
    secrets = {
        'smtp': [],
        'aws': [],
        'api_keys': [],
        'database': [],
        'debug_info': []
    }
    
    for category, patterns in LARAVEL_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
            if matches:
                if category in ['smtp_credentials']:
                    secrets['smtp'].extend(matches)
                elif category in ['aws_credentials']:
                    secrets['aws'].extend(matches)
                elif category in ['api_keys']:
                    secrets['api_keys'].extend(matches)
                elif category in ['database_urls']:
                    secrets['database'].extend(matches)
                elif category in ['ignition_debug']:
                    secrets['debug_info'].extend(matches)
    
    return secrets

def parse_env_file(content: str) -> Dict[str, str]:
    """Parse .env file content into key-value pairs"""
    env_vars = {}
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            env_vars[key] = value
    
    return env_vars

def generate_cidr_ips(cidr: str) -> List[str]:
    """Generate list of IPs from CIDR notation"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations"""
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename

def random_user_agent() -> str:
    """Generate random user agent string"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
    ]
    return random.choice(user_agents)

def encode_base64(text: str) -> str:
    """Encode text to base64"""
    return base64.b64encode(text.encode()).decode()

def decode_base64(encoded: str) -> str:
    """Decode base64 text"""
    try:
        return base64.b64decode(encoded).decode()
    except:
        return ""

def format_output(data: Any, output_format: str = 'json') -> str:
    """Format data for output"""
    if output_format.lower() == 'json':
        return json.dumps(data, indent=2, default=str)
    elif output_format.lower() == 'txt':
        if isinstance(data, dict):
            return '\n'.join([f"{k}: {v}" for k, v in data.items()])
        return str(data)
    return str(data)

def print_banner():
    """Print ASCII banner for the tool"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗     ██████╗  ██████╗ ║
║   ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗    ╚════██╗██╔═████╗║
║   ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝     █████╔╝██║██╔██║║
║   ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗    ██╔═══╝ ████╔╝██║║
║   ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║    ███████╗╚██████╔╝║
║    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ║
║                                                                               ║
║                   🔐 Laravel/API Env Exploiter 2025 🔐                       ║
║                     All-In-One Post-Research Edition                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

{Colors.YELLOW}[!] WARNING: This tool is for authorized security testing only!
[!] Unauthorized access to computer systems is illegal.
[!] Use only on systems you own or have explicit permission to test.

{Colors.GREEN}[+] Laravel Vulnerability Scanner & Credential Exploiter
[+] Mass IP/URL scanning with CIDR support
[+] Automatic secret extraction and live credential testing
[+] Multi-threaded performance up to 10,000 concurrent connections
{Colors.END}
    """
    print(banner)

def print_status(message: str, status: str = "info"):
    """Print colored status messages"""
    color_map = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
        "found": Colors.PURPLE
    }
    
    prefix_map = {
        "info": "[*]",
        "success": "[+]",
        "warning": "[!]",
        "error": "[-]",
        "found": "[!]"
    }
    
    color = color_map.get(status, Colors.WHITE)
    prefix = prefix_map.get(status, "[*]")
    
    print(f"{color}{prefix} {message}{Colors.END}")

def generate_random_string(length: int = 8) -> str:
    """Generate random string"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def is_laravel_app(content: str, headers: Dict[str, str]) -> bool:
    """Detect if target is running Laravel"""
    laravel_indicators = [
        'laravel_session',
        'X-Powered-By: Laravel',
        'laravel_token',
        '_token',
        'Illuminate\\',
        'Laravel Framework',
        'App\\Http\\',
        'bootstrap/app.php'
    ]
    
    # Check headers
    for header, value in headers.items():
        if any(indicator.lower() in value.lower() for indicator in laravel_indicators):
            return True
    
    # Check content
    return any(indicator in content for indicator in laravel_indicators)

def extract_csrf_token(content: str) -> Optional[str]:
    """Extract CSRF token from HTML content"""
    patterns = [
        r'<meta name="csrf-token" content="([^"]+)"',
        r'_token["\']?\s*:\s*["\']([^"\']+)["\']',
        r'csrf_token\(\)\s*:\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None