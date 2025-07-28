#!/usr/bin/env python3
"""
Laravel vulnerability scanner - Main scanning engine
Detects Laravel-specific vulnerabilities and exposures
"""

import asyncio
import os
import sys
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import json
import time

from core.http import HTTPScanner, test_connection, get_base_url, is_valid_target
from core.threads import ScanTask, create_scan_tasks, run_async_scan, ProgressTracker
from core.utils import (
    VULNERABLE_PATHS, print_status, print_banner, is_laravel_app,
    generate_cidr_ips, validate_ip, validate_url, Colors
)

class LaravelScanner:
    """Main Laravel vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get('timeout', 10)
        self.max_retries = config.get('max_retries', 3)
        self.max_workers = config.get('max_workers', 100)
        self.proxy = config.get('proxy')
        self.verify_ssl = config.get('verify_ssl', False)
        self.rate_limit = config.get('rate_limit', 10)  # requests per second
        self.results = []
        
        # Initialize HTTP scanner
        self.http_scanner = HTTPScanner(
            timeout=self.timeout,
            max_retries=self.max_retries,
            proxy=self.proxy,
            verify_ssl=self.verify_ssl
        )
    
    async def scan_targets(self, targets: List[str], paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan multiple targets for Laravel vulnerabilities
        """
        if not paths:
            paths = self._get_default_paths()
        
        print_status(f"Starting scan of {len(targets)} targets with {len(paths)} paths", "info")
        
        # Validate and prepare targets
        valid_targets = await self._prepare_targets(targets)
        if not valid_targets:
            print_status("No valid targets found", "error")
            return []
        
        print_status(f"Validated {len(valid_targets)} targets", "success")
        
        # Create scan tasks
        tasks = create_scan_tasks(valid_targets, paths)
        print_status(f"Created {len(tasks)} scan tasks", "info")
        
        # Run scanning
        results = await run_async_scan(tasks, self._scan_task_worker, self.max_workers)
        
        # Filter and process results
        vulnerable_results = [r for r in results if r and r.get('vulnerable', False)]
        
        print_status(f"Scan completed: {len(vulnerable_results)} vulnerabilities found", "success")
        self.results = vulnerable_results
        
        return vulnerable_results
    
    async def _scan_task_worker(self, task: ScanTask) -> Optional[Dict[str, Any]]:
        """Worker function for scanning individual tasks"""
        try:
            # Prepare target URL
            if not task.target.startswith(('http://', 'https://')):
                # Try both HTTP and HTTPS
                for scheme in ['https', 'http']:
                    test_url = f"{scheme}://{task.target}"
                    if await test_connection(test_url, timeout=5):
                        base_url = test_url
                        break
                else:
                    return None
            else:
                base_url = task.target
            
            # Perform the scan
            result = await self.http_scanner.scan_url(base_url, task.path)
            
            if result['vulnerable']:
                print_status(
                    f"🚨 VULNERABILITY FOUND: {result['vulnerability_type']} at {result['url']}", 
                    "found"
                )
            
            return result
            
        except Exception as e:
            print_status(f"Error scanning {task.target}{task.path}: {str(e)}", "error")
            return None
    
    async def _prepare_targets(self, targets: List[str]) -> List[str]:
        """Validate and prepare target list"""
        valid_targets = []
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            # Handle CIDR notation
            if '/' in target and validate_ip(target.split('/')[0]):
                cidr_ips = generate_cidr_ips(target)
                valid_targets.extend(cidr_ips[:1000])  # Limit CIDR expansion
                continue
            
            # Validate individual target
            if is_valid_target(target):
                valid_targets.append(target)
            else:
                print_status(f"Invalid target: {target}", "warning")
        
        return valid_targets
    
    def _get_default_paths(self) -> List[str]:
        """Get default Laravel vulnerability paths"""
        # Load additional paths from file if available
        additional_paths = []
        paths_file = os.path.join(os.path.dirname(__file__), 'data', 'paths.txt')
        
        if os.path.exists(paths_file):
            try:
                with open(paths_file, 'r') as f:
                    additional_paths = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print_status(f"Error loading paths file: {e}", "warning")
        
        # Combine default and additional paths
        all_paths = list(set(VULNERABLE_PATHS + additional_paths))
        
        print_status(f"Loaded {len(all_paths)} vulnerability paths", "info")
        return all_paths
    
    async def quick_scan(self, target: str) -> Dict[str, Any]:
        """Perform a quick scan on a single target with high-priority paths"""
        high_priority_paths = [
            '.env',
            '.env.backup',
            '.env.example',
            'vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
            '_ignition/execute-solution',
            'telescope/requests',
            'storage/logs/laravel.log',
            'config/app.php',
            'config/database.php'
        ]
        
        print_status(f"Quick scanning {target}", "info")
        
        results = await self.scan_targets([target], high_priority_paths)
        
        summary = {
            'target': target,
            'vulnerabilities_found': len(results),
            'vulnerabilities': results,
            'is_laravel': False,
            'scan_time': time.time()
        }
        
        # Check if target is running Laravel
        if results:
            for result in results:
                if result.get('content') and result.get('headers'):
                    if is_laravel_app(result['content'], result['headers']):
                        summary['is_laravel'] = True
                        break
        
        return summary
    
    async def deep_scan(self, target: str) -> Dict[str, Any]:
        """Perform a comprehensive deep scan on a single target"""
        print_status(f"Deep scanning {target}", "info")
        
        all_paths = self._get_default_paths()
        results = await self.scan_targets([target], all_paths)
        
        # Organize results by vulnerability type
        organized_results = {}
        for result in results:
            vuln_type = result.get('vulnerability_type', 'unknown')
            if vuln_type not in organized_results:
                organized_results[vuln_type] = []
            organized_results[vuln_type].append(result)
        
        summary = {
            'target': target,
            'total_vulnerabilities': len(results),
            'vulnerability_types': organized_results,
            'is_laravel': False,
            'scan_time': time.time(),
            'extracted_secrets': self._extract_all_secrets(results)
        }
        
        # Check if target is running Laravel
        for result in results:
            if result.get('content') and result.get('headers'):
                if is_laravel_app(result['content'], result['headers']):
                    summary['is_laravel'] = True
                    break
        
        return summary
    
    def _extract_all_secrets(self, results: List[Dict[str, Any]]) -> Dict[str, List]:
        """Extract all secrets from scan results"""
        all_secrets = {
            'smtp': [],
            'aws': [],
            'api_keys': [],
            'database': [],
            'debug_info': []
        }
        
        for result in results:
            if result.get('extracted_data', {}).get('secrets'):
                secrets = result['extracted_data']['secrets']
                for category, items in secrets.items():
                    if category in all_secrets:
                        all_secrets[category].extend(items)
        
        # Remove duplicates
        for category in all_secrets:
            all_secrets[category] = list(set(all_secrets[category]))
        
        return all_secrets
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        if not self.results:
            return {}
        
        stats = {
            'total_vulnerabilities': len(self.results),
            'vulnerability_types': {},
            'total_secrets_found': 0,
            'secrets_by_type': {
                'smtp': 0,
                'aws': 0,
                'api_keys': 0,
                'database': 0
            }
        }
        
        # Count vulnerability types
        for result in self.results:
            vuln_type = result.get('vulnerability_type', 'unknown')
            stats['vulnerability_types'][vuln_type] = stats['vulnerability_types'].get(vuln_type, 0) + 1
            
            # Count secrets
            if result.get('extracted_data', {}).get('secrets'):
                secrets = result['extracted_data']['secrets']
                for secret_type, items in secrets.items():
                    if secret_type in stats['secrets_by_type']:
                        stats['secrets_by_type'][secret_type] += len(items)
                        stats['total_secrets_found'] += len(items)
        
        return stats

def load_targets_from_file(filepath: str) -> List[str]:
    """Load targets from a text file"""
    targets = []
    
    if not os.path.exists(filepath):
        print_status(f"Target file not found: {filepath}", "error")
        return targets
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        
        print_status(f"Loaded {len(targets)} targets from {filepath}", "success")
    except Exception as e:
        print_status(f"Error loading targets from file: {e}", "error")
    
    return targets

def load_paths_from_file(filepath: str) -> List[str]:
    """Load custom paths from a text file"""
    paths = []
    
    if not os.path.exists(filepath):
        print_status(f"Paths file not found: {filepath}", "error")
        return paths
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    paths.append(line)
        
        print_status(f"Loaded {len(paths)} custom paths from {filepath}", "success")
    except Exception as e:
        print_status(f"Error loading paths from file: {e}", "error")
    
    return paths

async def main():
    """Main function for testing the scanner"""
    print_banner()
    
    # Default configuration
    config = {
        'timeout': 10,
        'max_retries': 3,
        'max_workers': 100,
        'proxy': None,
        'verify_ssl': False,
        'rate_limit': 10
    }
    
    # Example usage
    scanner = LaravelScanner(config)
    
    # Test with a single target
    test_targets = ['httpbin.org', 'example.com']
    
    results = await scanner.scan_targets(test_targets)
    
    print_status(f"Scan completed with {len(results)} vulnerabilities found", "info")
    
    # Print statistics
    stats = scanner.get_statistics()
    if stats:
        print_status(f"Statistics: {json.dumps(stats, indent=2)}", "info")

if __name__ == "__main__":
    asyncio.run(main())