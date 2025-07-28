#!/usr/bin/env python3
"""
Secret and credential extractor for Laravel applications
Extracts secrets from .env files, logs, API responses, and configuration files
"""

import re
import json
import base64
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs
import os

from core.utils import (
    extract_secrets_from_text, parse_env_file, print_status, Colors
)

class SecretExtractor:
    """Extract secrets and credentials from various sources"""
    
    def __init__(self):
        self.extracted_secrets = {
            'smtp': [],
            'aws': [],
            'sendgrid': [],
            'mailgun': [],
            'twilio': [],
            'stripe': [],
            'database': [],
            'api_keys': [],
            'tokens': [],
            'other': []
        }
        
        # Enhanced regex patterns for different secret types
        self.patterns = {
            'smtp': {
                'host': r'(?:MAIL_HOST|smtp[_\.]?host)\s*[:=]\s*["\']?([^"\'\s\n]+)',
                'port': r'(?:MAIL_PORT|smtp[_\.]?port)\s*[:=]\s*["\']?(\d+)',
                'username': r'(?:MAIL_USERNAME|smtp[_\.]?user(?:name)?)\s*[:=]\s*["\']?([^"\'\s\n]+)',
                'password': r'(?:MAIL_PASSWORD|smtp[_\.]?pass(?:word)?)\s*[:=]\s*["\']?([^"\'\s\n]+)',
                'from': r'(?:MAIL_FROM_ADDRESS|mail[_\.]?from)\s*[:=]\s*["\']?([^"\'\s\n]+)'
            },
            'aws': {
                'access_key': r'(?:AWS_ACCESS_KEY_ID|aws[_\.]?access[_\.]?key)\s*[:=]\s*["\']?([A-Z0-9]{20})',
                'secret_key': r'(?:AWS_SECRET_ACCESS_KEY|aws[_\.]?secret[_\.]?key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
                'region': r'(?:AWS_DEFAULT_REGION|aws[_\.]?region)\s*[:=]\s*["\']?([^"\'\s\n]+)',
                'bucket': r'(?:AWS_BUCKET|S3_BUCKET)\s*[:=]\s*["\']?([^"\'\s\n]+)'
            },
            'sendgrid': {
                'api_key': r'(?:SENDGRID_API_KEY|sendgrid[_\.]?key)\s*[:=]\s*["\']?(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})',
                'username': r'(?:SENDGRID_USERNAME|sendgrid[_\.]?user)\s*[:=]\s*["\']?([^"\'\s\n]+)'
            },
            'mailgun': {
                'domain': r'(?:MAILGUN_DOMAIN|mailgun[_\.]?domain)\s*[:=]\s*["\']?([^"\'\s\n]+)',
                'api_key': r'(?:MAILGUN_SECRET|mailgun[_\.]?key)\s*[:=]\s*["\']?(key-[a-f0-9]{32})',
                'public_key': r'(?:MAILGUN_PUBLIC_KEY|mailgun[_\.]?public)\s*[:=]\s*["\']?(pubkey-[a-f0-9]{32})'
            },
            'twilio': {
                'sid': r'(?:TWILIO_SID|twilio[_\.]?sid)\s*[:=]\s*["\']?(AC[a-f0-9]{32})',
                'token': r'(?:TWILIO_TOKEN|twilio[_\.]?token)\s*[:=]\s*["\']?([a-f0-9]{32})',
                'phone': r'(?:TWILIO_PHONE|twilio[_\.]?from)\s*[:=]\s*["\']?([+]?[\d\-\(\)\s]+)'
            },
            'stripe': {
                'publishable': r'(?:STRIPE_KEY|stripe[_\.]?public)\s*[:=]\s*["\']?(pk_live_[A-Za-z0-9]{24}|pk_test_[A-Za-z0-9]{24})',
                'secret': r'(?:STRIPE_SECRET|stripe[_\.]?secret)\s*[:=]\s*["\']?(sk_live_[A-Za-z0-9]{24}|sk_test_[A-Za-z0-9]{24})'
            },
            'database': {
                'mysql_url': r'mysql://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/([^?\s]+)',
                'postgres_url': r'postgres(?:ql)?://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/([^?\s]+)',
                'mongodb_url': r'mongodb://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/([^?\s]+)',
                'redis_url': r'redis://(?:([^:]+):([^@]+)@)?([^:/]+)(?::(\d+))?(?:/(\d+))?'
            },
            'tokens': {
                'jwt': r'[eE]y[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*',
                'bearer': r'[Bb]earer\s+([A-Za-z0-9\-._~+/]+=*)',
                'api_token': r'(?:api[_\.]?token|access[_\.]?token)\s*[:=]\s*["\']?([A-Za-z0-9\-._~+/=]{20,})'
            }
        }
    
    def extract_from_env_file(self, content: str, source_url: str = "") -> Dict[str, Any]:
        """Extract secrets from .env file content"""
        print_status(f"Extracting secrets from .env file: {source_url}", "info")
        
        env_vars = parse_env_file(content)
        secrets = {
            'source': source_url,
            'type': 'env_file',
            'credentials': {}
        }
        
        # Extract SMTP credentials
        smtp_creds = self._extract_smtp_from_env(env_vars)
        if smtp_creds:
            secrets['credentials']['smtp'] = smtp_creds
            self.extracted_secrets['smtp'].append(smtp_creds)
        
        # Extract AWS credentials
        aws_creds = self._extract_aws_from_env(env_vars)
        if aws_creds:
            secrets['credentials']['aws'] = aws_creds
            self.extracted_secrets['aws'].append(aws_creds)
        
        # Extract API keys
        api_keys = self._extract_api_keys_from_env(env_vars)
        if api_keys:
            secrets['credentials']['api_keys'] = api_keys
            for service, creds in api_keys.items():
                if service in self.extracted_secrets:
                    self.extracted_secrets[service].append(creds)
        
        # Extract database URLs
        db_creds = self._extract_database_from_env(env_vars)
        if db_creds:
            secrets['credentials']['database'] = db_creds
            self.extracted_secrets['database'].extend(db_creds)
        
        return secrets
    
    def extract_from_log_file(self, content: str, source_url: str = "") -> Dict[str, Any]:
        """Extract secrets from log file content"""
        print_status(f"Extracting secrets from log file: {source_url}", "info")
        
        secrets = {
            'source': source_url,
            'type': 'log_file',
            'credentials': {},
            'debug_info': []
        }
        
        # Extract credentials mentioned in logs
        creds = self._extract_from_text(content)
        if creds:
            secrets['credentials'] = creds
        
        # Extract debug/error information
        debug_info = self._extract_debug_info(content)
        if debug_info:
            secrets['debug_info'] = debug_info
        
        return secrets
    
    def extract_from_api_response(self, content: str, headers: Dict[str, str], 
                                  source_url: str = "") -> Dict[str, Any]:
        """Extract secrets from API response"""
        print_status(f"Extracting secrets from API response: {source_url}", "info")
        
        secrets = {
            'source': source_url,
            'type': 'api_response',
            'credentials': {},
            'tokens': []
        }
        
        # Try to parse as JSON
        try:
            json_data = json.loads(content)
            json_secrets = self._extract_from_json(json_data)
            if json_secrets:
                secrets['credentials'].update(json_secrets)
        except json.JSONDecodeError:
            pass
        
        # Extract from text content
        text_secrets = self._extract_from_text(content)
        if text_secrets:
            for key, value in text_secrets.items():
                if key in secrets['credentials']:
                    secrets['credentials'][key].extend(value)
                else:
                    secrets['credentials'][key] = value
        
        # Extract tokens from headers
        header_tokens = self._extract_tokens_from_headers(headers)
        if header_tokens:
            secrets['tokens'] = header_tokens
        
        return secrets
    
    def extract_from_config_file(self, content: str, source_url: str = "") -> Dict[str, Any]:
        """Extract secrets from configuration files"""
        print_status(f"Extracting secrets from config file: {source_url}", "info")
        
        secrets = {
            'source': source_url,
            'type': 'config_file',
            'credentials': {}
        }
        
        # Try different parsing strategies
        if source_url.endswith('.json'):
            try:
                json_data = json.loads(content)
                json_secrets = self._extract_from_json(json_data)
                if json_secrets:
                    secrets['credentials'] = json_secrets
            except json.JSONDecodeError:
                pass
        
        # Extract from text regardless of format
        text_secrets = self._extract_from_text(content)
        if text_secrets:
            for key, value in text_secrets.items():
                if key in secrets['credentials']:
                    secrets['credentials'][key].extend(value)
                else:
                    secrets['credentials'][key] = value
        
        return secrets
    
    def _extract_smtp_from_env(self, env_vars: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Extract SMTP credentials from environment variables"""
        smtp_keys = ['MAIL_HOST', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_FROM_ADDRESS']
        smtp_creds = {}
        
        for key, value in env_vars.items():
            if key in smtp_keys and value:
                smtp_creds[key.lower().replace('mail_', '')] = value
        
        return smtp_creds if len(smtp_creds) >= 2 else None
    
    def _extract_aws_from_env(self, env_vars: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Extract AWS credentials from environment variables"""
        aws_keys = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION', 'AWS_BUCKET']
        aws_creds = {}
        
        for key, value in env_vars.items():
            if key in aws_keys and value:
                aws_creds[key.lower().replace('aws_', '')] = value
        
        return aws_creds if 'access_key_id' in aws_creds and 'secret_access_key' in aws_creds else None
    
    def _extract_api_keys_from_env(self, env_vars: Dict[str, str]) -> Dict[str, Dict[str, str]]:
        """Extract API keys from environment variables"""
        api_services = {}
        
        # SendGrid
        if 'SENDGRID_API_KEY' in env_vars:
            api_services['sendgrid'] = {'api_key': env_vars['SENDGRID_API_KEY']}
        
        # Mailgun
        mailgun_keys = {}
        for key in ['MAILGUN_DOMAIN', 'MAILGUN_SECRET', 'MAILGUN_PUBLIC_KEY']:
            if key in env_vars:
                mailgun_keys[key.lower().replace('mailgun_', '')] = env_vars[key]
        if mailgun_keys:
            api_services['mailgun'] = mailgun_keys
        
        # Twilio
        twilio_keys = {}
        for key in ['TWILIO_SID', 'TWILIO_TOKEN', 'TWILIO_PHONE']:
            if key in env_vars:
                twilio_keys[key.lower().replace('twilio_', '')] = env_vars[key]
        if twilio_keys:
            api_services['twilio'] = twilio_keys
        
        # Stripe
        stripe_keys = {}
        for key in ['STRIPE_KEY', 'STRIPE_SECRET']:
            if key in env_vars:
                stripe_keys[key.lower().replace('stripe_', '')] = env_vars[key]
        if stripe_keys:
            api_services['stripe'] = stripe_keys
        
        return api_services
    
    def _extract_database_from_env(self, env_vars: Dict[str, str]) -> List[Dict[str, str]]:
        """Extract database connection strings"""
        databases = []
        
        # Look for database URLs
        url_keys = ['DATABASE_URL', 'DB_URL', 'MYSQL_URL', 'POSTGRES_URL', 'MONGODB_URI', 'REDIS_URL']
        
        for key, value in env_vars.items():
            if key in url_keys and value:
                db_info = self._parse_database_url(value)
                if db_info:
                    db_info['env_key'] = key
                    databases.append(db_info)
        
        return databases
    
    def _parse_database_url(self, url: str) -> Optional[Dict[str, str]]:
        """Parse database URL into components"""
        try:
            parsed = urlparse(url)
            
            return {
                'type': parsed.scheme,
                'host': parsed.hostname,
                'port': str(parsed.port) if parsed.port else '',
                'username': parsed.username or '',
                'password': parsed.password or '',
                'database': parsed.path.lstrip('/') if parsed.path else '',
                'url': url
            }
        except:
            return None
    
    def _extract_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract secrets from plain text using regex patterns"""
        found_secrets = {}
        
        for category, patterns in self.patterns.items():
            found_secrets[category] = []
            
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if isinstance(match, tuple):
                        # For database URLs with multiple groups
                        if category == 'database':
                            db_info = {
                                'username': match[0] if len(match) > 0 else '',
                                'password': match[1] if len(match) > 1 else '',
                                'host': match[2] if len(match) > 2 else '',
                                'port': match[3] if len(match) > 3 else '',
                                'database': match[4] if len(match) > 4 else ''
                            }
                            found_secrets[category].append(db_info)
                        else:
                            found_secrets[category].extend(match)
                    else:
                        found_secrets[category].append(match)
        
        # Remove empty categories
        return {k: v for k, v in found_secrets.items() if v}
    
    def _extract_from_json(self, data: Any, path: str = "") -> Dict[str, List[str]]:
        """Recursively extract secrets from JSON data"""
        secrets = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if key indicates a secret
                if self._is_secret_key(key.lower()):
                    category = self._categorize_secret_key(key.lower())
                    if category not in secrets:
                        secrets[category] = []
                    secrets[category].append(str(value))
                
                # Recurse into nested structures
                nested_secrets = self._extract_from_json(value, current_path)
                for cat, items in nested_secrets.items():
                    if cat not in secrets:
                        secrets[cat] = []
                    secrets[cat].extend(items)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                nested_secrets = self._extract_from_json(item, f"{path}[{i}]")
                for cat, items in nested_secrets.items():
                    if cat not in secrets:
                        secrets[cat] = []
                    secrets[cat].extend(items)
        
        elif isinstance(data, str):
            # Check if string value contains secrets
            text_secrets = self._extract_from_text(data)
            for cat, items in text_secrets.items():
                if cat not in secrets:
                    secrets[cat] = []
                secrets[cat].extend(items)
        
        return secrets
    
    def _is_secret_key(self, key: str) -> bool:
        """Check if a key name indicates it might contain a secret"""
        secret_indicators = [
            'password', 'pass', 'pwd', 'secret', 'key', 'token', 'auth',
            'credential', 'api_key', 'access_token', 'bearer'
        ]
        return any(indicator in key for indicator in secret_indicators)
    
    def _categorize_secret_key(self, key: str) -> str:
        """Categorize a secret key"""
        if any(smtp_indicator in key for smtp_indicator in ['mail', 'smtp']):
            return 'smtp'
        elif any(aws_indicator in key for aws_indicator in ['aws', 's3']):
            return 'aws'
        elif 'sendgrid' in key:
            return 'sendgrid'
        elif 'mailgun' in key:
            return 'mailgun'
        elif 'twilio' in key:
            return 'twilio'
        elif 'stripe' in key:
            return 'stripe'
        elif any(db_indicator in key for db_indicator in ['db', 'database', 'mysql', 'postgres', 'mongo', 'redis']):
            return 'database'
        else:
            return 'api_keys'
    
    def _extract_tokens_from_headers(self, headers: Dict[str, str]) -> List[str]:
        """Extract tokens from HTTP headers"""
        tokens = []
        
        for header, value in headers.items():
            if header.lower() in ['authorization', 'x-api-key', 'x-auth-token']:
                if 'bearer' in value.lower():
                    token = value.split(' ')[-1]
                    tokens.append(token)
                elif header.lower() in ['x-api-key', 'x-auth-token']:
                    tokens.append(value)
        
        return tokens
    
    def _extract_debug_info(self, content: str) -> List[Dict[str, str]]:
        """Extract debug information from logs"""
        debug_patterns = [
            r'(?i)(exception|error|warning|fatal):\s*(.+)',
            r'(?i)at\s+([^\s]+)\s+line\s+(\d+)',
            r'(?i)file:\s*(.+\.php)',
            r'(?i)stack\s+trace:(.+?)(?=\n\n|\n\[|\Z)',
        ]
        
        debug_info = []
        
        for pattern in debug_patterns:
            matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)
            for match in matches:
                if isinstance(match, tuple):
                    debug_info.append({
                        'type': match[0] if len(match) > 0 else 'unknown',
                        'details': match[1] if len(match) > 1 else ''
                    })
                else:
                    debug_info.append({'type': 'info', 'details': match})
        
        return debug_info
    
    def get_all_secrets(self) -> Dict[str, List]:
        """Get all extracted secrets organized by type"""
        return self.extracted_secrets
    
    def get_secrets_summary(self) -> Dict[str, int]:
        """Get a summary count of extracted secrets"""
        summary = {}
        for category, secrets in self.extracted_secrets.items():
            summary[category] = len(secrets)
        return summary
    
    def clear_secrets(self):
        """Clear all extracted secrets"""
        for category in self.extracted_secrets:
            self.extracted_secrets[category] = []

def test_extractor():
    """Test the secret extractor with sample data"""
    extractor = SecretExtractor()
    
    # Test .env file
    sample_env = """
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:SAMPLE_KEY_HERE
APP_DEBUG=true
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=secret123

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=test@example.com
MAIL_PASSWORD=password123
MAIL_ENCRYPTION=tls

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-west-2

SENDGRID_API_KEY=SG.SAMPLE_KEY_HERE.SAMPLE_SIGNATURE
    """
    
    result = extractor.extract_from_env_file(sample_env, "test.env")
    print(f"Extracted from .env: {json.dumps(result, indent=2)}")
    
    # Test summary
    summary = extractor.get_secrets_summary()
    print(f"Secrets summary: {summary}")

if __name__ == "__main__":
    test_extractor()