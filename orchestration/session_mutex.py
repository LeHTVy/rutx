"""
Snode Security Framework - Session Mutex for Safe Concurrent Operations

Enables parallel scanning while preventing race conditions in session updates.
"""

import threading
import asyncio
import time
from pathlib import Path
from typing import Dict, List, Any, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class SessionMutex:
    """Thread-safe mutex manager for concurrent session operations"""

    def __init__(self):
        self._locks: Dict[str, threading.Lock] = {}
        self._lock_creation_mutex = threading.Lock()

    def get_lock(self, session_id: str) -> threading.Lock:
        """Get or create a lock for a specific session"""
        if session_id not in self._locks:
            with self._lock_creation_mutex:
                # Double-check pattern to avoid race condition
                if session_id not in self._locks:
                    self._locks[session_id] = threading.Lock()
        return self._locks[session_id]

    def lock(self, session_id: str):
        """Context manager for safe session locking"""
        return self.get_lock(session_id)


class ParallelScanner:
    """Manages parallel scanning operations with session safety"""

    def __init__(self, session_id: str, mutex: Optional[SessionMutex] = None):
        self.session_id = session_id
        self.mutex = mutex or SessionMutex()
        self.results: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []

    def scan_batch_parallel(
        self,
        targets: List[str],
        scan_function: Callable,
        batch_size: int = 50,
        max_workers: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Scan targets in parallel batches

        Args:
            targets: List of targets to scan
            scan_function: Function to call for each batch (takes list of targets)
            batch_size: Number of targets per batch
            max_workers: Maximum concurrent workers

        Returns:
            List of scan results
        """
        # Split targets into batches
        batches = [
            targets[i:i + batch_size]
            for i in range(0, len(targets), batch_size)
        ]

        print(f"\n[Parallel Scan] Processing {len(targets)} targets in {len(batches)} batches")
        print(f"  Batch size: {batch_size}")
        print(f"  Max workers: {max_workers}")

        results = []
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all batches
            future_to_batch = {
                executor.submit(self._safe_scan_batch, batch_idx, batch, scan_function): batch_idx
                for batch_idx, batch in enumerate(batches)
            }

            # Collect results as they complete
            for future in as_completed(future_to_batch):
                batch_idx = future_to_batch[future]
                try:
                    batch_result = future.result()
                    results.append(batch_result)

                    # Safe progress update with mutex
                    with self.mutex.lock(self.session_id):
                        completed_batches = len(results)
                        progress = (completed_batches / len(batches)) * 100
                        print(f"  Progress: {completed_batches}/{len(batches)} batches ({progress:.1f}%)")

                except Exception as e:
                    error = {
                        'batch_idx': batch_idx,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
                    self.errors.append(error)
                    print(f"  [ERROR] Batch {batch_idx} failed: {e}")

        elapsed = time.time() - start_time
        print(f"\n[Parallel Scan] Completed in {elapsed:.2f}s")
        print(f"  Success: {len(results)}/{len(batches)} batches")
        print(f"  Errors: {len(self.errors)}")

        return results

    def _safe_scan_batch(
        self,
        batch_idx: int,
        batch: List[str],
        scan_function: Callable
    ) -> Dict[str, Any]:
        """Execute scan for a batch with error handling"""
        try:
            result = scan_function(batch)
            return {
                'batch_idx': batch_idx,
                'batch_size': len(batch),
                'targets': batch,
                'result': result,
                'success': True,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'batch_idx': batch_idx,
                'batch_size': len(batch),
                'targets': batch,
                'error': str(e),
                'success': False,
                'timestamp': datetime.now().isoformat()
            }

    def scan_targets_parallel(
        self,
        targets: List[str],
        scan_function: Callable,
        max_workers: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Scan individual targets in parallel (not batched)

        Args:
            targets: List of targets to scan
            scan_function: Function to call for each target (takes single target)
            max_workers: Maximum concurrent workers

        Returns:
            List of scan results
        """
        print(f"\n[Parallel Scan] Processing {len(targets)} targets individually")
        print(f"  Max workers: {max_workers}")

        results = []
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all targets
            future_to_target = {
                executor.submit(self._safe_scan_target, idx, target, scan_function): idx
                for idx, target in enumerate(targets)
            }

            # Collect results
            completed = 0
            for future in as_completed(future_to_target):
                try:
                    result = future.result()
                    results.append(result)

                    # Thread-safe progress update
                    completed += 1
                    if completed % 10 == 0 or completed == len(targets):
                        progress = (completed / len(targets)) * 100
                        print(f"  Progress: {completed}/{len(targets)} targets ({progress:.1f}%)")

                except Exception as e:
                    print(f"  [ERROR] Target scan failed: {e}")

        elapsed = time.time() - start_time
        successful = sum(1 for r in results if r.get('success'))
        print(f"\n[Parallel Scan] Completed in {elapsed:.2f}s")
        print(f"  Success: {successful}/{len(targets)} targets")

        return results

    def _safe_scan_target(
        self,
        idx: int,
        target: str,
        scan_function: Callable
    ) -> Dict[str, Any]:
        """Execute scan for a single target with error handling"""
        try:
            result = scan_function(target)
            return {
                'idx': idx,
                'target': target,
                'result': result,
                'success': True,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'idx': idx,
                'target': target,
                'error': str(e),
                'success': False,
                'timestamp': datetime.now().isoformat()
            }


# Async version for asyncio-based tools
class AsyncParallelScanner:
    """Async version of parallel scanner for asyncio-based operations"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.results: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def scan_batch_async(
        self,
        targets: List[str],
        scan_function: Callable,
        batch_size: int = 50,
        max_concurrent: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Scan targets in parallel batches using asyncio

        Args:
            targets: List of targets
            scan_function: Async function to call for each batch
            batch_size: Targets per batch
            max_concurrent: Max concurrent batches

        Returns:
            List of scan results
        """
        batches = [
            targets[i:i + batch_size]
            for i in range(0, len(targets), batch_size)
        ]

        print(f"\n[Async Scan] Processing {len(targets)} targets in {len(batches)} batches")
        print(f"  Max concurrent: {max_concurrent}")

        results = []
        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_with_semaphore(batch_idx: int, batch: List[str]):
            async with semaphore:
                try:
                    result = await scan_function(batch)
                    async with self._lock:
                        results.append({
                            'batch_idx': batch_idx,
                            'result': result,
                            'success': True
                        })
                        print(f"  Progress: {len(results)}/{len(batches)} batches")
                except Exception as e:
                    async with self._lock:
                        self.errors.append({
                            'batch_idx': batch_idx,
                            'error': str(e)
                        })

        # Run all batches concurrently (with semaphore limiting)
        await asyncio.gather(*[
            scan_with_semaphore(idx, batch)
            for idx, batch in enumerate(batches)
        ])

        return results


# Singleton instance
_global_mutex = SessionMutex()

def get_session_mutex() -> SessionMutex:
    """Get the global session mutex instance"""
    return _global_mutex


# Example usage
if __name__ == "__main__":
    import random

    # Simulate a scan function
    def mock_naabu_scan(targets: List[str]) -> Dict[str, Any]:
        """Mock scan that takes 0.5-2 seconds"""
        time.sleep(random.uniform(0.5, 2.0))

        # Simulate finding ports on some targets
        results = {}
        for target in targets:
            if random.random() > 0.3:  # 70% chance of finding ports
                results[target] = [80, 443, random.choice([22, 3306, 8080])]

        return {
            'targets_scanned': len(targets),
            'targets_with_ports': len(results),
            'results': results
        }

    # Test parallel scanning
    print("="*60)
    print("SESSION MUTEX & PARALLEL SCANNING TEST")
    print("="*60)

    # Create test data
    test_subdomains = [f"subdomain{i}.example.com" for i in range(100)]

    # Create parallel scanner
    session_id = "test-parallel-001"
    scanner = ParallelScanner(session_id)

    # Run parallel batch scan
    results = scanner.scan_batch_parallel(
        targets=test_subdomains,
        scan_function=mock_naabu_scan,
        batch_size=20,
        max_workers=5
    )

    # Analyze results
    total_targets_scanned = sum(
        r['result']['targets_scanned']
        for r in results if r.get('success')
    )
    total_with_ports = sum(
        r['result']['targets_with_ports']
        for r in results if r.get('success')
    )

    print(f"\n[SUCCESS] Parallel scan test completed")
    print(f"  Total targets scanned: {total_targets_scanned}")
    print(f"  Targets with open ports: {total_with_ports}")
    print(f"  Success rate: {(len(results) - len(scanner.errors))/len(results)*100:.1f}%")
