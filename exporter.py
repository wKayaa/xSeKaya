#!/usr/bin/env python3
"""
Export module for saving scan results in multiple formats
Supports JSON, CSV, TXT, and webhook notifications
"""

import json
import csv
import os
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional
from datetime import datetime
import xml.etree.ElementTree as ET

from core.utils import print_status, sanitize_filename, format_output

class ResultExporter:
    """Export scan results to various formats"""
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        self.ensure_output_directory()
    
    def ensure_output_directory(self):
        """Create output directory if it doesn't exist"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print_status(f"Created output directory: {self.output_dir}", "info")
    
    def export_json(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Export data to JSON format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cracker_scan_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, sanitize_filename(filename))
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            print_status(f"Results exported to JSON: {filepath}", "success")
            return filepath
        
        except Exception as e:
            print_status(f"Error exporting to JSON: {str(e)}", "error")
            return ""
    
    def export_csv(self, vulnerabilities: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """Export vulnerabilities to CSV format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cracker_vulnerabilities_{timestamp}.csv"
        
        filepath = os.path.join(self.output_dir, sanitize_filename(filename))
        
        if not vulnerabilities:
            print_status("No vulnerabilities to export", "warning")
            return ""
        
        try:
            fieldnames = [
                'url', 'vulnerability_type', 'status_code', 'content_length',
                'has_secrets', 'secret_types', 'timestamp'
            ]
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for vuln in vulnerabilities:
                    # Prepare row data
                    row = {
                        'url': vuln.get('url', ''),
                        'vulnerability_type': vuln.get('vulnerability_type', ''),
                        'status_code': vuln.get('status_code', ''),
                        'content_length': vuln.get('content_length', 0),
                        'has_secrets': bool(vuln.get('extracted_data', {}).get('secrets')),
                        'secret_types': ', '.join(vuln.get('extracted_data', {}).get('secrets', {}).keys()),
                        'timestamp': datetime.now().isoformat()
                    }
                    writer.writerow(row)
            
            print_status(f"Vulnerabilities exported to CSV: {filepath}", "success")
            return filepath
        
        except Exception as e:
            print_status(f"Error exporting to CSV: {str(e)}", "error")
            return ""
    
    def export_txt(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Export data to human-readable text format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cracker_report_{timestamp}.txt"
        
        filepath = os.path.join(self.output_dir, sanitize_filename(filename))
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("CRACKER SCANNER 2025 - VULNERABILITY REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Summary
                if 'summary' in data:
                    f.write("SCAN SUMMARY\n")
                    f.write("-" * 40 + "\n")
                    summary = data['summary']
                    f.write(f"Total targets scanned: {summary.get('total_targets', 0)}\n")
                    f.write(f"Total vulnerabilities found: {summary.get('total_vulnerabilities', 0)}\n")
                    f.write(f"Total secrets extracted: {summary.get('total_secrets', 0)}\n")
                    f.write(f"Scan duration: {summary.get('duration', 0):.2f} seconds\n\n")
                
                # Vulnerabilities
                if 'vulnerabilities' in data:
                    f.write("VULNERABILITIES FOUND\n")
                    f.write("-" * 40 + "\n")
                    
                    for i, vuln in enumerate(data['vulnerabilities'], 1):
                        f.write(f"\n[{i}] {vuln.get('vulnerability_type', 'Unknown').upper()}\n")
                        f.write(f"URL: {vuln.get('url', '')}\n")
                        f.write(f"Status: {vuln.get('status_code', '')}\n")
                        f.write(f"Content Length: {vuln.get('content_length', 0)} bytes\n")
                        
                        # Extracted secrets
                        if vuln.get('extracted_data', {}).get('secrets'):
                            f.write("Extracted Secrets:\n")
                            secrets = vuln['extracted_data']['secrets']
                            for secret_type, items in secrets.items():
                                if items:
                                    f.write(f"  - {secret_type.upper()}: {len(items)} item(s)\n")
                                    for item in items[:3]:  # Show first 3 items
                                        f.write(f"    * {str(item)[:50]}...\n")
                        f.write("-" * 40 + "\n")
                
                # Valid credentials
                if 'valid_credentials' in data:
                    f.write("\nVALID CREDENTIALS FOUND\n")
                    f.write("-" * 40 + "\n")
                    
                    for service, creds in data['valid_credentials'].items():
                        if creds:
                            f.write(f"\n{service.upper()} Credentials:\n")
                            for i, cred in enumerate(creds, 1):
                                f.write(f"  [{i}] {cred.get('credentials', {})}\n")
                                f.write(f"      Response: {cred.get('response', '')}\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("End of Report\n")
                f.write("=" * 80 + "\n")
            
            print_status(f"Report exported to TXT: {filepath}", "success")
            return filepath
        
        except Exception as e:
            print_status(f"Error exporting to TXT: {str(e)}", "error")
            return ""
    
    def export_xml(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Export data to XML format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cracker_scan_{timestamp}.xml"
        
        filepath = os.path.join(self.output_dir, sanitize_filename(filename))
        
        try:
            root = ET.Element("cracker_scan")
            root.set("timestamp", datetime.now().isoformat())
            
            # Add summary
            if 'summary' in data:
                summary_elem = ET.SubElement(root, "summary")
                for key, value in data['summary'].items():
                    elem = ET.SubElement(summary_elem, key)
                    elem.text = str(value)
            
            # Add vulnerabilities
            if 'vulnerabilities' in data:
                vulns_elem = ET.SubElement(root, "vulnerabilities")
                
                for vuln in data['vulnerabilities']:
                    vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                    
                    for key, value in vuln.items():
                        if key == 'extracted_data':
                            # Handle nested data
                            data_elem = ET.SubElement(vuln_elem, "extracted_data")
                            if 'secrets' in value:
                                secrets_elem = ET.SubElement(data_elem, "secrets")
                                for secret_type, items in value['secrets'].items():
                                    type_elem = ET.SubElement(secrets_elem, secret_type)
                                    for item in items:
                                        item_elem = ET.SubElement(type_elem, "item")
                                        item_elem.text = str(item)
                        else:
                            elem = ET.SubElement(vuln_elem, key)
                            elem.text = str(value)
            
            # Write XML file
            tree = ET.ElementTree(root)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            print_status(f"Results exported to XML: {filepath}", "success")
            return filepath
        
        except Exception as e:
            print_status(f"Error exporting to XML: {str(e)}", "error")
            return ""
    
    def export_secrets_only(self, secrets: Dict[str, List], filename: Optional[str] = None) -> str:
        """Export only extracted secrets to JSON format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"extracted_secrets_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, sanitize_filename(filename))
        
        try:
            # Filter out empty secret categories
            filtered_secrets = {k: v for k, v in secrets.items() if v}
            
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'total_secrets': sum(len(v) for v in filtered_secrets.values()),
                'secrets_by_type': {k: len(v) for k, v in filtered_secrets.items()},
                'secrets': filtered_secrets
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str, ensure_ascii=False)
            
            print_status(f"Secrets exported to JSON: {filepath}", "success")
            return filepath
        
        except Exception as e:
            print_status(f"Error exporting secrets: {str(e)}", "error")
            return ""
    
    def export_all_formats(self, data: Dict[str, Any], base_filename: Optional[str] = None) -> Dict[str, str]:
        """Export data to all supported formats"""
        if not base_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"cracker_scan_{timestamp}"
        
        results = {}
        
        # Export to each format
        results['json'] = self.export_json(data, f"{base_filename}.json")
        results['txt'] = self.export_txt(data, f"{base_filename}.txt")
        results['xml'] = self.export_xml(data, f"{base_filename}.xml")
        
        # Export CSV if vulnerabilities exist
        if 'vulnerabilities' in data and data['vulnerabilities']:
            results['csv'] = self.export_csv(data['vulnerabilities'], f"{base_filename}_vulnerabilities.csv")
        
        # Export secrets separately if they exist
        if 'extracted_secrets' in data and data['extracted_secrets']:
            results['secrets'] = self.export_secrets_only(data['extracted_secrets'], f"{base_filename}_secrets.json")
        
        return results

class WebhookNotifier:
    """Send notifications via webhooks"""
    
    def __init__(self, webhook_url: str, timeout: int = 10):
        self.webhook_url = webhook_url
        self.timeout = timeout
    
    async def send_notification(self, data: Dict[str, Any], 
                              notification_type: str = "scan_complete") -> bool:
        """Send notification via webhook"""
        try:
            payload = {
                'type': notification_type,
                'timestamp': datetime.now().isoformat(),
                'data': data
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status < 400:
                        print_status(f"Webhook notification sent successfully", "success")
                        return True
                    else:
                        print_status(f"Webhook failed with status {response.status}", "error")
                        return False
        
        except Exception as e:
            print_status(f"Webhook notification failed: {str(e)}", "error")
            return False
    
    async def send_vulnerability_alert(self, vulnerability: Dict[str, Any]) -> bool:
        """Send immediate alert for critical vulnerability"""
        alert_data = {
            'severity': 'high',
            'vulnerability_type': vulnerability.get('vulnerability_type', ''),
            'url': vulnerability.get('url', ''),
            'has_secrets': bool(vulnerability.get('extracted_data', {}).get('secrets')),
            'timestamp': datetime.now().isoformat()
        }
        
        return await self.send_notification(alert_data, "vulnerability_found")

class SlackNotifier:
    """Send notifications to Slack"""
    
    def __init__(self, webhook_url: str, timeout: int = 10):
        self.webhook_url = webhook_url
        self.timeout = timeout
    
    async def send_scan_summary(self, summary: Dict[str, Any]) -> bool:
        """Send scan summary to Slack"""
        try:
            # Format Slack message
            text = f"🔐 *Cracker Scanner 2025 - Scan Complete*\n\n"
            text += f"• Total vulnerabilities found: *{summary.get('total_vulnerabilities', 0)}*\n"
            text += f"• Total secrets extracted: *{summary.get('total_secrets', 0)}*\n"
            text += f"• Scan duration: *{summary.get('duration', 0):.2f}s*\n"
            
            if summary.get('vulnerability_types'):
                text += f"\n*Vulnerability Types:*\n"
                for vuln_type, count in summary['vulnerability_types'].items():
                    text += f"• {vuln_type}: {count}\n"
            
            payload = {
                'text': text,
                'username': 'CrackerScanner2025',
                'icon_emoji': ':lock:'
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status == 200:
                        print_status(f"Slack notification sent successfully", "success")
                        return True
                    else:
                        print_status(f"Slack notification failed with status {response.status}", "error")
                        return False
        
        except Exception as e:
            print_status(f"Slack notification failed: {str(e)}", "error")
            return False
    
    async def send_vulnerability_alert(self, vulnerability: Dict[str, Any]) -> bool:
        """Send critical vulnerability alert to Slack"""
        try:
            vuln_type = vulnerability.get('vulnerability_type', 'Unknown')
            url = vulnerability.get('url', '')
            has_secrets = bool(vulnerability.get('extracted_data', {}).get('secrets'))
            
            text = f"🚨 *VULNERABILITY FOUND* 🚨\n\n"
            text += f"• Type: *{vuln_type}*\n"
            text += f"• URL: `{url}`\n"
            text += f"• Contains secrets: *{'Yes' if has_secrets else 'No'}*\n"
            
            if has_secrets:
                secrets = vulnerability['extracted_data']['secrets']
                text += f"\n*Secret types found:*\n"
                for secret_type, items in secrets.items():
                    if items:
                        text += f"• {secret_type}: {len(items)} item(s)\n"
            
            payload = {
                'text': text,
                'username': 'CrackerScanner2025',
                'icon_emoji': ':warning:'
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status == 200:
                        print_status(f"Slack vulnerability alert sent", "success")
                        return True
                    else:
                        print_status(f"Slack alert failed with status {response.status}", "error")
                        return False
        
        except Exception as e:
            print_status(f"Slack vulnerability alert failed: {str(e)}", "error")
            return False

def create_scan_summary(vulnerabilities: List[Dict[str, Any]], 
                       valid_credentials: Dict[str, List], 
                       scan_duration: float,
                       targets_scanned: int) -> Dict[str, Any]:
    """Create a comprehensive scan summary"""
    
    # Count vulnerability types
    vulnerability_types = {}
    total_secrets = 0
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get('vulnerability_type', 'unknown')
        vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        # Count secrets
        if vuln.get('extracted_data', {}).get('secrets'):
            secrets = vuln['extracted_data']['secrets']
            for items in secrets.values():
                total_secrets += len(items)
    
    # Count valid credentials
    total_valid_creds = sum(len(creds) for creds in valid_credentials.values())
    
    summary = {
        'timestamp': datetime.now().isoformat(),
        'total_targets': targets_scanned,
        'total_vulnerabilities': len(vulnerabilities),
        'total_secrets': total_secrets,
        'total_valid_credentials': total_valid_creds,
        'duration': scan_duration,
        'vulnerability_types': vulnerability_types,
        'valid_credentials_by_service': {
            service: len(creds) for service, creds in valid_credentials.items()
        }
    }
    
    return summary

async def test_exporter():
    """Test the export functionality"""
    exporter = ResultExporter("test_results")
    
    # Sample data
    test_data = {
        'summary': {
            'total_targets': 10,
            'total_vulnerabilities': 5,
            'total_secrets': 15,
            'duration': 120.5
        },
        'vulnerabilities': [
            {
                'url': 'https://example.com/.env',
                'vulnerability_type': 'env_exposed',
                'status_code': 200,
                'content_length': 1024,
                'extracted_data': {
                    'secrets': {
                        'smtp': ['user@example.com', 'password123'],
                        'aws': ['AKIATEST', 'secret_key']
                    }
                }
            }
        ],
        'valid_credentials': {
            'smtp': [
                {
                    'credentials': {'host': 'smtp.example.com', 'username': 'test'},
                    'valid': True,
                    'response': 'Success'
                }
            ]
        }
    }
    
    # Test all export formats
    results = exporter.export_all_formats(test_data)
    print(f"Export results: {results}")

if __name__ == "__main__":
    asyncio.run(test_exporter())