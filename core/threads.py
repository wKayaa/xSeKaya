#!/usr/bin/env python3
"""
Threading and worker pool management for concurrent scanning
Handles thread pool execution and task distribution
"""

import asyncio
import concurrent.futures
from typing import List, Callable, Any, Dict, Optional
import threading
import time
import queue
from dataclasses import dataclass

from .utils import print_status

@dataclass
class ScanTask:
    """Represents a single scan task"""
    target: str
    path: str
    task_id: str
    metadata: Dict[str, Any] = None

class ThreadPoolManager:
    """Manages thread pool for concurrent operations"""
    
    def __init__(self, max_workers: int = 100, timeout: int = 30):
        self.max_workers = min(max_workers, 10000)  # Cap at 10k as per requirements
        self.timeout = timeout
        self.executor = None
        self.results_queue = queue.Queue()
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'start_time': None,
            'end_time': None
        }
    
    def __enter__(self):
        """Context manager entry"""
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="CrackerScanner"
        )
        self.stats['start_time'] = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if self.executor:
            self.executor.shutdown(wait=True)
        self.stats['end_time'] = time.time()
    
    def submit_task(self, func: Callable, *args, **kwargs) -> concurrent.futures.Future:
        """Submit a task to the thread pool"""
        if not self.executor:
            raise RuntimeError("ThreadPoolManager not initialized. Use context manager.")
        
        self.stats['total_tasks'] += 1
        future = self.executor.submit(func, *args, **kwargs)
        future.add_done_callback(self._task_callback)
        return future
    
    def _task_callback(self, future: concurrent.futures.Future):
        """Callback for completed tasks"""
        try:
            result = future.result()
            self.stats['completed_tasks'] += 1
            self.results_queue.put(('success', result))
        except Exception as e:
            self.stats['failed_tasks'] += 1
            self.results_queue.put(('error', str(e)))
    
    def get_results(self, timeout: Optional[float] = None) -> List[Any]:
        """Get all results from completed tasks"""
        results = []
        while True:
            try:
                result_type, result_data = self.results_queue.get(timeout=timeout)
                results.append(result_data)
            except queue.Empty:
                break
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        stats = self.stats.copy()
        if stats['start_time'] and stats['end_time']:
            stats['duration'] = stats['end_time'] - stats['start_time']
            stats['tasks_per_second'] = stats['completed_tasks'] / stats['duration'] if stats['duration'] > 0 else 0
        return stats

class AsyncWorkerPool:
    """Async worker pool for high-performance scanning"""
    
    def __init__(self, max_workers: int = 1000, semaphore_limit: int = 500):
        self.max_workers = min(max_workers, 10000)
        self.semaphore_limit = min(semaphore_limit, 5000)
        self.semaphore = None
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'start_time': None,
            'end_time': None
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.semaphore = asyncio.Semaphore(self.semaphore_limit)
        self.stats['start_time'] = time.time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        self.stats['end_time'] = time.time()
    
    async def run_tasks(self, tasks: List[ScanTask], worker_func: Callable) -> List[Any]:
        """Run tasks concurrently with semaphore limiting"""
        self.stats['total_tasks'] = len(tasks)
        
        async def limited_worker(task: ScanTask):
            async with self.semaphore:
                try:
                    result = await worker_func(task)
                    self.stats['completed_tasks'] += 1
                    return result
                except Exception as e:
                    self.stats['failed_tasks'] += 1
                    print_status(f"Task failed for {task.target}{task.path}: {str(e)}", "error")
                    return None
        
        # Create coroutines for all tasks
        coroutines = [limited_worker(task) for task in tasks]
        
        # Run with progress reporting
        results = []
        batch_size = 100
        
        for i in range(0, len(coroutines), batch_size):
            batch = coroutines[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            results.extend([r for r in batch_results if r is not None])
            
            # Progress reporting
            progress = min(i + batch_size, len(coroutines))
            percentage = (progress / len(coroutines)) * 100
            print_status(f"Progress: {progress}/{len(coroutines)} ({percentage:.1f}%)", "info")
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        stats = self.stats.copy()
        if stats['start_time'] and stats['end_time']:
            stats['duration'] = stats['end_time'] - stats['start_time']
            stats['tasks_per_second'] = stats['completed_tasks'] / stats['duration'] if stats['duration'] > 0 else 0
        return stats

class RateLimiter:
    """Rate limiter to control request frequency"""
    
    def __init__(self, calls_per_second: float = 10.0):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_called = 0.0
        self.lock = threading.Lock()
    
    def acquire(self):
        """Acquire rate limit token"""
        with self.lock:
            now = time.time()
            time_since_last = now - self.last_called
            
            if time_since_last < self.min_interval:
                sleep_time = self.min_interval - time_since_last
                time.sleep(sleep_time)
            
            self.last_called = time.time()

class ProgressTracker:
    """Track and display progress of scanning operations"""
    
    def __init__(self, total_tasks: int):
        self.total_tasks = total_tasks
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.last_update = 0
    
    def update(self, completed: int = 1, failed: int = 0):
        """Update progress counters"""
        with self.lock:
            self.completed_tasks += completed
            self.failed_tasks += failed
            
            # Print progress every 100 tasks or every 5 seconds
            now = time.time()
            if (self.completed_tasks + self.failed_tasks) % 100 == 0 or now - self.last_update > 5:
                self._print_progress()
                self.last_update = now
    
    def _print_progress(self):
        """Print current progress"""
        total_processed = self.completed_tasks + self.failed_tasks
        percentage = (total_processed / self.total_tasks) * 100 if self.total_tasks > 0 else 0
        elapsed = time.time() - self.start_time
        
        if elapsed > 0:
            rate = total_processed / elapsed
            eta = (self.total_tasks - total_processed) / rate if rate > 0 else 0
            
            print_status(
                f"Progress: {total_processed}/{self.total_tasks} ({percentage:.1f}%) "
                f"- Rate: {rate:.1f}/s - ETA: {eta:.0f}s - Failed: {self.failed_tasks}",
                "info"
            )
    
    def finish(self):
        """Print final statistics"""
        elapsed = time.time() - self.start_time
        rate = self.completed_tasks / elapsed if elapsed > 0 else 0
        
        print_status(
            f"Scan completed: {self.completed_tasks} successful, {self.failed_tasks} failed "
            f"in {elapsed:.1f}s (avg {rate:.1f}/s)",
            "success"
        )

def create_scan_tasks(targets: List[str], paths: List[str]) -> List[ScanTask]:
    """Create scan tasks from targets and paths"""
    tasks = []
    task_id = 0
    
    for target in targets:
        for path in paths:
            tasks.append(ScanTask(
                target=target,
                path=path,
                task_id=f"task_{task_id:06d}",
                metadata={'created_at': time.time()}
            ))
            task_id += 1
    
    return tasks

def batch_tasks(tasks: List[ScanTask], batch_size: int = 100) -> List[List[ScanTask]]:
    """Split tasks into batches for processing"""
    batches = []
    for i in range(0, len(tasks), batch_size):
        batches.append(tasks[i:i + batch_size])
    return batches

async def run_async_scan(tasks: List[ScanTask], worker_func: Callable, 
                        max_workers: int = 1000) -> List[Any]:
    """High-level function to run async scanning"""
    print_status(f"Starting async scan with {len(tasks)} tasks using {max_workers} workers", "info")
    
    async with AsyncWorkerPool(max_workers=max_workers) as pool:
        results = await pool.run_tasks(tasks, worker_func)
        stats = pool.get_stats()
        
        print_status(
            f"Async scan completed: {stats['completed_tasks']} completed, "
            f"{stats['failed_tasks']} failed in {stats.get('duration', 0):.1f}s "
            f"({stats.get('tasks_per_second', 0):.1f} tasks/s)",
            "success"
        )
        
        return results

def run_threaded_scan(tasks: List[ScanTask], worker_func: Callable, 
                     max_workers: int = 100) -> List[Any]:
    """High-level function to run threaded scanning"""
    print_status(f"Starting threaded scan with {len(tasks)} tasks using {max_workers} workers", "info")
    
    with ThreadPoolManager(max_workers=max_workers) as pool:
        futures = []
        
        for task in tasks:
            future = pool.submit_task(worker_func, task)
            futures.append(future)
        
        # Wait for completion
        concurrent.futures.wait(futures, timeout=None)
        
        results = []
        for future in futures:
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print_status(f"Task execution error: {str(e)}", "error")
        
        stats = pool.get_stats()
        print_status(
            f"Threaded scan completed: {stats['completed_tasks']} completed, "
            f"{stats['failed_tasks']} failed in {stats.get('duration', 0):.1f}s "
            f"({stats.get('tasks_per_second', 0):.1f} tasks/s)",
            "success"
        )
        
        return results