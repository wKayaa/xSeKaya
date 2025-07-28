#!/usr/bin/env python3
"""
Live credential checker for testing extracted secrets
Tests SMTP, AWS, SendGrid, and other API credentials
"""

import asyncio
import aiohttp
import smtplib
import ssl
import json
import base64
from typing import Dict, List, Optional, Tuple, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket

from core.utils import print_status, Colors

class CredentialChecker:
    """Test extracted credentials against live services"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results = {
            'smtp': [],
            'aws': [],
            'sendgrid': [],
            'mailgun': [],
            'twilio': [],
            'stripe': []
        }
    
    async def check_all_credentials(self, credentials: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """Check all types of credentials"""
        print_status("Starting credential validation checks", "info")
        
        tasks = []
        
        # Check SMTP credentials
        if 'smtp' in credentials:
            for smtp_creds in credentials['smtp']:
                tasks.append(self.check_smtp_credentials(smtp_creds))
        
        # Check AWS credentials
        if 'aws' in credentials:
            for aws_creds in credentials['aws']:
                tasks.append(self.check_aws_credentials(aws_creds))
        
        # Check SendGrid credentials
        if 'sendgrid' in credentials:
            for sg_creds in credentials['sendgrid']:
                tasks.append(self.check_sendgrid_credentials(sg_creds))
        
        # Check Mailgun credentials
        if 'mailgun' in credentials:
            for mg_creds in credentials['mailgun']:
                tasks.append(self.check_mailgun_credentials(mg_creds))
        
        # Check Twilio credentials
        if 'twilio' in credentials:
            for tw_creds in credentials['twilio']:
                tasks.append(self.check_twilio_credentials(tw_creds))
        
        # Check Stripe credentials
        if 'stripe' in credentials:
            for stripe_creds in credentials['stripe']:
                tasks.append(self.check_stripe_credentials(stripe_creds))
        
        # Execute all checks concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        return self.results
    
    async def check_smtp_credentials(self, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Test SMTP credentials by attempting to connect and authenticate"""
        print_status(f"Testing SMTP credentials for {credentials.get('host', 'unknown')}", "info")
        
        result = {
            'type': 'smtp',
            'credentials': credentials,
            'valid': False,
            'error': None,
            'response': None
        }
        
        try:
            host = credentials.get('host', '')
            port = int(credentials.get('port', 587))
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            
            if not all([host, username, password]):
                result['error'] = 'Missing required SMTP credentials'
                return result
            
            # Test connection in a separate thread to avoid blocking
            loop = asyncio.get_event_loop()
            smtp_result = await loop.run_in_executor(
                None, 
                self._test_smtp_connection,
                host, port, username, password
            )
            
            result.update(smtp_result)
            
            if result['valid']:
                print_status(f"✅ SMTP credentials VALID: {username}@{host}", "success")
            else:
                print_status(f"❌ SMTP credentials INVALID: {username}@{host} - {result['error']}", "error")
        
        except Exception as e:
            result['error'] = str(e)
            print_status(f"❌ SMTP test failed: {str(e)}", "error")
        
        self.results['smtp'].append(result)
        return result
    
    def _test_smtp_connection(self, host: str, port: int, username: str, password: str) -> Dict[str, Any]:
        """Test SMTP connection synchronously"""
        try:
            # Try different connection methods
            for use_tls in [True, False]:
                try:
                    if port in [465, 587] or use_tls:
                        # Use TLS/SSL
                        context = ssl.create_default_context()
                        server = smtplib.SMTP(host, port, timeout=self.timeout)
                        server.starttls(context=context)
                    else:
                        # Plain connection
                        server = smtplib.SMTP(host, port, timeout=self.timeout)
                    
                    # Try to authenticate
                    server.login(username, password)
                    server.quit()
                    
                    return {
                        'valid': True,
                        'response': f'Successfully authenticated to {host}:{port}',
                        'connection_type': 'TLS' if use_tls else 'Plain'
                    }
                
                except smtplib.SMTPAuthenticationError as e:
                    return {
                        'valid': False,
                        'error': f'Authentication failed: {str(e)}'
                    }
                
                except Exception as e:
                    if not use_tls:  # Try TLS next
                        continue
                    return {
                        'valid': False,
                        'error': f'Connection failed: {str(e)}'
                    }
            
            return {
                'valid': False,
                'error': 'Could not establish connection with any method'
            }
        
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    async def check_aws_credentials(self, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Test AWS credentials using STS GetCallerIdentity"""
        print_status("Testing AWS credentials", "info")
        
        result = {
            'type': 'aws',
            'credentials': credentials,
            'valid': False,
            'error': None,
            'response': None
        }
        
        try:
            access_key = credentials.get('access_key_id', '')
            secret_key = credentials.get('secret_access_key', '')
            region = credentials.get('region', 'us-east-1')
            
            if not all([access_key, secret_key]):
                result['error'] = 'Missing AWS access key or secret key'
                return result
            
            # Use AWS STS GetCallerIdentity to test credentials
            aws_result = await self._test_aws_sts(access_key, secret_key, region)
            result.update(aws_result)
            
            if result['valid']:
                print_status(f"✅ AWS credentials VALID: {access_key}", "success")
            else:
                print_status(f"❌ AWS credentials INVALID: {access_key} - {result['error']}", "error")
        
        except Exception as e:
            result['error'] = str(e)
            print_status(f"❌ AWS test failed: {str(e)}", "error")
        
        self.results['aws'].append(result)
        return result
    
    async def _test_aws_sts(self, access_key: str, secret_key: str, region: str) -> Dict[str, Any]:
        """Test AWS credentials using STS GetCallerIdentity API"""
        try:
            import hashlib
            import hmac
            from datetime import datetime
            
            # AWS STS endpoint
            endpoint = f"https://sts.{region}.amazonaws.com/"
            service = 'sts'
            
            # Create request
            timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            date = timestamp[:8]
            
            # Request parameters
            params = {
                'Action': 'GetCallerIdentity',
                'Version': '2011-06-15'
            }
            
            # Create canonical request
            canonical_querystring = '&'.join([f"{k}={v}" for k, v in sorted(params.items())])
            canonical_headers = f"host:sts.{region}.amazonaws.com\nx-amz-date:{timestamp}\n"
            signed_headers = "host;x-amz-date"
            
            canonical_request = f"POST\n/\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{hashlib.sha256(''.encode()).hexdigest()}"
            
            # Create string to sign
            algorithm = 'AWS4-HMAC-SHA256'
            credential_scope = f"{date}/{region}/{service}/aws4_request"
            string_to_sign = f"{algorithm}\n{timestamp}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
            
            # Calculate signature
            def sign(key, msg):
                return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
            
            def getSignatureKey(key, dateStamp, regionName, serviceName):
                kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
                kRegion = sign(kDate, regionName)
                kService = sign(kRegion, serviceName)
                kSigning = sign(kService, 'aws4_request')
                return kSigning
            
            signing_key = getSignatureKey(secret_key, date, region, service)
            signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
            
            # Create authorization header
            authorization_header = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
            
            headers = {
                'Authorization': authorization_header,
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                'X-Amz-Date': timestamp
            }
            
            # Make request
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(endpoint, headers=headers, data=canonical_querystring) as response:
                    response_text = await response.text()
                    
                    if response.status == 200:
                        return {
                            'valid': True,
                            'response': response_text
                        }
                    else:
                        return {
                            'valid': False,
                            'error': f'AWS API error: {response.status} - {response_text}'
                        }
        
        except Exception as e:
            return {
                'valid': False,
                'error': f'AWS STS test failed: {str(e)}'
            }
    
    async def check_sendgrid_credentials(self, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Test SendGrid API key"""
        print_status("Testing SendGrid credentials", "info")
        
        result = {
            'type': 'sendgrid',
            'credentials': credentials,
            'valid': False,
            'error': None,
            'response': None
        }
        
        try:
            api_key = credentials.get('api_key', '')
            
            if not api_key:
                result['error'] = 'Missing SendGrid API key'
                return result
            
            # Test API key using SendGrid API
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                # Test with account information endpoint
                async with session.get('https://api.sendgrid.com/v3/user/account', headers=headers) as response:
                    response_text = await response.text()
                    
                    if response.status == 200:
                        result['valid'] = True
                        result['response'] = 'SendGrid API key is valid'
                        print_status(f"✅ SendGrid API key VALID", "success")
                    else:
                        result['error'] = f'SendGrid API error: {response.status} - {response_text}'
                        print_status(f"❌ SendGrid API key INVALID - {result['error']}", "error")
        
        except Exception as e:
            result['error'] = str(e)
            print_status(f"❌ SendGrid test failed: {str(e)}", "error")
        
        self.results['sendgrid'].append(result)
        return result
    
    async def check_mailgun_credentials(self, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Test Mailgun API credentials"""
        print_status("Testing Mailgun credentials", "info")
        
        result = {
            'type': 'mailgun',
            'credentials': credentials,
            'valid': False,
            'error': None,
            'response': None
        }
        
        try:
            api_key = credentials.get('secret', '')
            domain = credentials.get('domain', '')
            
            if not api_key:
                result['error'] = 'Missing Mailgun API key'
                return result
            
            # Test API key using Mailgun API
            auth = aiohttp.BasicAuth('api', api_key)
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                # Test with domain stats endpoint
                url = f'https://api.mailgun.net/v3/{domain}/stats/total' if domain else 'https://api.mailgun.net/v3/domains'
                
                async with session.get(url, auth=auth) as response:
                    response_text = await response.text()
                    
                    if response.status == 200:
                        result['valid'] = True
                        result['response'] = 'Mailgun API key is valid'
                        print_status(f"✅ Mailgun API key VALID", "success")
                    else:
                        result['error'] = f'Mailgun API error: {response.status} - {response_text}'
                        print_status(f"❌ Mailgun API key INVALID - {result['error']}", "error")
        
        except Exception as e:
            result['error'] = str(e)
            print_status(f"❌ Mailgun test failed: {str(e)}", "error")
        
        self.results['mailgun'].append(result)
        return result
    
    async def check_twilio_credentials(self, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Test Twilio API credentials"""
        print_status("Testing Twilio credentials", "info")
        
        result = {
            'type': 'twilio',
            'credentials': credentials,
            'valid': False,
            'error': None,
            'response': None
        }
        
        try:
            sid = credentials.get('sid', '')
            token = credentials.get('token', '')
            
            if not all([sid, token]):
                result['error'] = 'Missing Twilio SID or token'
                return result
            
            # Test credentials using Twilio API
            auth_string = base64.b64encode(f'{sid}:{token}'.encode()).decode()
            headers = {
                'Authorization': f'Basic {auth_string}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                # Test with account information endpoint
                url = f'https://api.twilio.com/2010-04-01/Accounts/{sid}.json'
                
                async with session.get(url, headers=headers) as response:
                    response_text = await response.text()
                    
                    if response.status == 200:
                        result['valid'] = True
                        result['response'] = 'Twilio credentials are valid'
                        print_status(f"✅ Twilio credentials VALID", "success")
                    else:
                        result['error'] = f'Twilio API error: {response.status} - {response_text}'
                        print_status(f"❌ Twilio credentials INVALID - {result['error']}", "error")
        
        except Exception as e:
            result['error'] = str(e)
            print_status(f"❌ Twilio test failed: {str(e)}", "error")
        
        self.results['twilio'].append(result)
        return result
    
    async def check_stripe_credentials(self, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Test Stripe API credentials"""
        print_status("Testing Stripe credentials", "info")
        
        result = {
            'type': 'stripe',
            'credentials': credentials,
            'valid': False,
            'error': None,
            'response': None
        }
        
        try:
            # Try both publishable and secret keys
            for key_type in ['publishable', 'secret']:
                api_key = credentials.get(key_type, '')
                if not api_key:
                    continue
                
                headers = {
                    'Authorization': f'Bearer {api_key}',
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                    # Test with account information endpoint
                    async with session.get('https://api.stripe.com/v1/account', headers=headers) as response:
                        response_text = await response.text()
                        
                        if response.status == 200:
                            result['valid'] = True
                            result['response'] = f'Stripe {key_type} key is valid'
                            print_status(f"✅ Stripe {key_type} key VALID", "success")
                            break
                        else:
                            result['error'] = f'Stripe API error: {response.status} - {response_text}'
            
            if not result['valid'] and result['error']:
                print_status(f"❌ Stripe credentials INVALID - {result['error']}", "error")
        
        except Exception as e:
            result['error'] = str(e)
            print_status(f"❌ Stripe test failed: {str(e)}", "error")
        
        self.results['stripe'].append(result)
        return result
    
    def get_valid_credentials(self) -> Dict[str, List[Dict]]:
        """Get only the valid credentials"""
        valid_creds = {}
        
        for service, results in self.results.items():
            valid_creds[service] = [r for r in results if r.get('valid', False)]
        
        return valid_creds
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of credential check results"""
        summary = {
            'total_checked': 0,
            'total_valid': 0,
            'by_service': {}
        }
        
        for service, results in self.results.items():
            checked = len(results)
            valid = len([r for r in results if r.get('valid', False)])
            
            summary['total_checked'] += checked
            summary['total_valid'] += valid
            summary['by_service'][service] = {
                'checked': checked,
                'valid': valid,
                'invalid': checked - valid
            }
        
        return summary

async def test_checker():
    """Test the credential checker with sample data"""
    checker = CredentialChecker()
    
    # Sample credentials (these are fake and will fail)
    test_credentials = {
        'smtp': [{
            'host': 'smtp.gmail.com',
            'port': '587',
            'username': 'test@gmail.com',
            'password': 'fake_password'
        }],
        'aws': [{
            'access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'region': 'us-west-2'
        }],
        'sendgrid': [{
            'api_key': 'SG.fake_key_here'
        }]
    }
    
    results = await checker.check_all_credentials(test_credentials)
    summary = checker.get_summary()
    
    print(f"Check results: {json.dumps(summary, indent=2)}")

if __name__ == "__main__":
    asyncio.run(test_checker())