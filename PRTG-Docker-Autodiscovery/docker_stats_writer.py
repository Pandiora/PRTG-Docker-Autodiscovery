#!/usr/bin/env python3
"""
PRTG Docker Container Stats - POLL SCRIPT (Write to SHM)
Version: 3.3.0

PERFORMANCE OPTIMIZED + SHARED MEMORY WRITER + DEBUG MODE:
- Uses docker inspect (1x for all containers)
- Reads /proc for CPU, memory, network, Block I/O (PRIMARY method)
- CPU cache eliminates sleep on subsequent runs
- Network as bytes/sec rate (delta like CPU)
- Single du command for volumes (~750ms sequential, low CPU impact)
- Single du command for container UpperDir (~65ms)
- Image size from Docker API (~64ms for 22 containers)
- Fast PID discovery via /proc/*/cgroup scan (~3ms)
- NO docker stats API (too slow!)
- NO filesystem traversal (MergedDir avoided)
- **Writes all metrics to /dev/shm for sensor scripts to read**

Expected Performance:
- 22 containers WITHOUT disk: ~200ms
- 22 containers WITH disk: ~1000ms (volumes ~750ms sequential + containers ~65ms)

Multi-Probe Setup:
- THIS SCRIPT (poll): Collects all metrics → writes to shm
- SENSOR SCRIPT: Reads from shm (use docker_stats_read.py)
- Cache location: /dev/shm/prtg_docker_metrics/<container_name>.json

Metrics Collected (per container):
- Health Status (healthy/unhealthy)
- CPU % (with cache for no-sleep subsequent runs)
- Memory Usage/% (uses host memory if no container limit)
- Network RX/TX bytes/sec (rate)
- Block I/O Read/Write bytes
- Disk Usage: Container Data (writable layer), Container (full), Volumes, Total
- Log File Size
- Uptime seconds
- Restart Count

Usage:
    # Collect all containers and write to shm (scheduled via cron/systemd)
    python3 docker_stats_poll.py [--perf] [--verbose] [--debug]
    
    # For reading individual containers, use docker_stats_read.py instead:
    python3 docker_stats_read.py <container_name>
    
    Flags:
        --perf           Show performance report + resource usage (CPU/RAM impact)
        --verbose, -v    Show per-container timing details
        --debug          Show detailed debug output (volumes, I/O, logs, etc.)
"""

import sys
import os

# Auto-elevate to root if needed
if os.geteuid() != 0:
    import subprocess
    print("Not running as root, re-executing with sudo...", file=sys.stderr)
    args = ['sudo', sys.executable] + sys.argv
    os.execvp('sudo', args)

# Now continue with rest of imports
import json
import glob
import time
from datetime import datetime
from collections import defaultdict

try:
    import docker
except ImportError:
    print(json.dumps({
        "version": 2,
        "status": "error",
        "message": "Docker Python SDK required: pip install docker"
    }))
    sys.exit(1)

VERSION = "3.3.1"

# Cache configuration
CACHE_DIR = "/dev/shm/prtg_docker_cpu_cache"  # CPU cache
NETWORK_CACHE_DIR = "/dev/shm/prtg_docker_network_cache"  # Network cache
METRICS_CACHE_DIR = "/dev/shm/prtg_docker_metrics"  # Metrics cache

# Performance tracking
perf_timings = defaultdict(float)
perf_tracking_enabled = False
debug_enabled = False


def perf_track(func):
    """Decorator to track function execution time (only when perf tracking enabled)."""
    def wrapper(*args, **kwargs):
        if perf_tracking_enabled:
            start = time.time()
            result = func(*args, **kwargs)
            duration = (time.time() - start) * 1000
            perf_timings[func.__name__] += duration
            return result
        else:
            return func(*args, **kwargs)
    return wrapper


def debug_print(message):
    """Print debug message if debug mode is enabled."""
    if debug_enabled:
        print(f"[DEBUG] {message}", file=sys.stderr)


class ResourceTracker:
    """Track script's own resource usage."""
    def __init__(self):
        self.start_time = time.time()
        self.start_cpu = self._get_cpu_time()
        self.start_mem = self._get_memory()
        self.peak_mem = 0
    
    def _get_cpu_time(self):
        """Get process CPU time (user + system) in seconds."""
        try:
            with open('/proc/self/stat', 'r') as f:
                fields = f.read().split()
                utime = int(fields[13])  # User time
                stime = int(fields[14])  # System time
                return (utime + stime) / 100.0  # Convert from ticks to seconds
        except:
            return 0
    
    def _get_memory(self):
        """Get process memory usage (RSS) in bytes."""
        try:
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        kb = int(line.split()[1])
                        return kb * 1024
            return 0
        except:
            return 0
    
    def update_peak_mem(self):
        """Update peak memory if current is higher."""
        current = self._get_memory()
        if current > self.peak_mem:
            self.peak_mem = current
    
    def get_stats(self):
        """Get resource usage statistics."""
        end_time = time.time()
        end_cpu = self._get_cpu_time()
        end_mem = self._get_memory()
        
        wall_time = end_time - self.start_time
        cpu_time = end_cpu - self.start_cpu
        cpu_percent = (cpu_time / wall_time * 100) if wall_time > 0 else 0
        
        return {
            'wall_time_ms': wall_time * 1000,
            'cpu_time_ms': cpu_time * 1000,
            'cpu_percent': cpu_percent,
            'peak_mem_mb': self.peak_mem / (1024 * 1024),
            'final_mem_mb': end_mem / (1024 * 1024)
        }


# ============================================================================
# CPU CACHE (existing)
# ============================================================================

def get_cpu_cache_file(container_name):
    """Get CPU cache file path for a container."""
    from pathlib import Path
    Path(CACHE_DIR).mkdir(exist_ok=True)
    return os.path.join(CACHE_DIR, f"{container_name}_cpu.json")


def get_cached_cpu(container_name):
    """Get cached CPU ticks - no expiry, just use if exists."""
    cache_file = get_cpu_cache_file(container_name)
    
    if not os.path.exists(cache_file):
        return None, None
    
    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
        return cache_data.get('cpu_ticks'), cache_data.get('timestamp')
    except:
        return None, None


def save_cpu_cache(container_name, cpu_ticks):
    """Save CPU ticks to cache."""
    cache_file = get_cpu_cache_file(container_name)
    cache_data = {
        'timestamp': time.time(),
        'cpu_ticks': cpu_ticks
    }
    
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)
    except:
        pass


# ============================================================================
# NETWORK CACHE (for rate calculation between runs)
# ============================================================================

def get_network_cache_file(container_name):
    """Get network cache file path for a container."""
    from pathlib import Path
    Path(NETWORK_CACHE_DIR).mkdir(exist_ok=True)
    return os.path.join(NETWORK_CACHE_DIR, f"{container_name}_net.json")


def get_cached_network(container_name):
    """Get cached network counters - no expiry, just use if exists."""
    cache_file = get_network_cache_file(container_name)
    
    if not os.path.exists(cache_file):
        return None, None, None
    
    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
        return cache_data.get('rx_bytes'), cache_data.get('tx_bytes'), cache_data.get('timestamp')
    except:
        return None, None, None


def save_network_cache(container_name, rx_bytes, tx_bytes):
    """Save network counters to cache."""
    cache_file = get_network_cache_file(container_name)
    cache_data = {
        'timestamp': time.time(),
        'rx_bytes': rx_bytes,
        'tx_bytes': tx_bytes
    }
    
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)
    except:
        pass


# ============================================================================
# METRICS CACHE (NEW)
# ============================================================================

def get_metrics_cache_file(container_name):
    """Get metrics cache file path for a container."""
    from pathlib import Path
    Path(METRICS_CACHE_DIR).mkdir(exist_ok=True)
    return os.path.join(METRICS_CACHE_DIR, f"{container_name}.json")


def create_prtg_json(container_name, metrics):
    """
    Create PRTG Script V2 JSON response from metrics.
    
    Channel IDs (fixed):
    - 10: Health Status
    - 11: CPU Usage
    - 12: Memory Usage (bytes, auto-scaled)
    - 13: Memory Usage %
    - 14: Network RX Rate (bytes/sec)
    - 15: Network TX Rate (bytes/sec)
    - 16: Block I/O Read (bytes)
    - 17: Block I/O Write (bytes)
    - 18: Disk - Container Data (bytes)
    - 19: Disk - Container (bytes)
    - 20: Disk - Volumes (bytes)
    - 21: Disk - Total (bytes)
    - 22: Log File Size (bytes)
    - 23: Uptime (seconds)
    - 24: Restart Count
    """
    m = metrics
    
    debug_print(f"create_prtg_json for {container_name}: network_rx_rate={m.get('network_rx_rate', 'MISSING')}, disk_volumes={m.get('disk_volumes', 'MISSING')}")
    
    channels = [
        {
            "id": 10,
            "name": "Health Status",
            "type": "integer",
            "value": m['health_status'],
            "kind": "custom",
            "display_unit": "status"
        },
        {
            "id": 11,
            "name": "CPU Usage",
            "type": "float",
            "value": m['cpu_percent'],
            "kind": "percent"
        },
        {
            "id": 12,
            "name": "Memory Usage",
            "type": "integer",
            "value": m['memory_usage'],
            "kind": "size_bytes_memory"
        },
        {
            "id": 13,
            "name": "Memory Usage %",
            "type": "float",
            "value": m['memory_percent'],
            "kind": "percent"
        },
        {
            "id": 14,
            "name": "Network RX Rate",
            "type": "integer",
            "value": int(round(m['network_rx_rate'])),
            "kind": "size_bytes_bandwidth"
        },
        {
            "id": 15,
            "name": "Network TX Rate",
            "type": "integer",
            "value": int(round(m['network_tx_rate'])),
            "kind": "size_bytes_bandwidth"
        },
        {
            "id": 16,
            "name": "Block I/O Read",
            "type": "integer",
            "value": m['block_io_read'],
            "kind": "size_bytes_disk"
        },
        {
            "id": 17,
            "name": "Block I/O Write",
            "type": "integer",
            "value": m['block_io_write'],
            "kind": "size_bytes_disk"
        },
        {
            "id": 18,
            "name": "Disk Usage - Container Data",
            "type": "integer",
            "value": m['disk_container_data'],
            "kind": "size_bytes_disk"
        },
        {
            "id": 19,
            "name": "Disk Usage - Container",
            "type": "integer",
            "value": m['disk_container'],
            "kind": "size_bytes_disk"
        },
        {
            "id": 20,
            "name": "Disk Usage - Volumes",
            "type": "integer",
            "value": m['disk_volumes'],
            "kind": "size_bytes_disk"
        },
        {
            "id": 21,
            "name": "Disk Usage - Total",
            "type": "integer",
            "value": m['disk_total'],
            "kind": "size_bytes_disk"
        },
        {
            "id": 22,
            "name": "Log File Size",
            "type": "integer",
            "value": m['log_size'],
            "kind": "size_bytes_disk"
        },
        {
            "id": 23,
            "name": "Uptime",
            "type": "integer",
            "value": m['uptime_seconds'],
            "kind": "time_seconds"
        },
        {
            "id": 24,
            "name": "Restart Count",
            "type": "integer",
            "value": m['restart_count'],
            "kind": "count"
        }
    ]
    
    return {
        "version": 2,
        "status": "ok",
        "message": f"Docker stats for: {container_name}",
        "channels": channels
    }


@perf_track
def save_metrics_cache(container_name, metrics):
    """Save complete Script V2 JSON to cache with timestamp."""
    cache_file = get_metrics_cache_file(container_name)
    
    debug_print(f"save_metrics_cache for {container_name}: Network RX/TX rate={metrics.get('network_rx_rate', 'MISSING')}/{metrics.get('network_tx_rate', 'MISSING')}")
    
    # Create complete Script V2 JSON
    script_v2_json = create_prtg_json(container_name, metrics)
    
    cache_data = {
        'timestamp': time.time(),
        'script_v2_json': script_v2_json
    }
    
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)
        debug_print(f"Saved metrics cache for {container_name}")
    except Exception as e:
        print(f"Warning: Failed to save metrics cache for {container_name}: {e}", file=sys.stderr)


@perf_track
def save_all_metrics_cache(all_metrics):
    """Save metrics for all containers to cache."""
    for container_name, metrics in all_metrics.items():
        save_metrics_cache(container_name, metrics)


# ============================================================================
# DOCKER INSPECT (Fast bulk operation)
# ============================================================================

@perf_track
def get_all_container_info():
    """Get basic info for ALL containers via docker inspect (single call)."""
    try:
        client = docker.from_env()
        containers = client.containers.list(filters={"status": "running"})
        
        debug_print(f"Found {len(containers)} running containers")
        
        # First, scan /proc/*/cgroup once to map all container IDs to PIDs (~3ms)
        container_id_to_pids = {}
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            
            cgroup_file = f'/proc/{pid}/cgroup'
            try:
                with open(cgroup_file, 'r') as f:
                    content = f.read()
                    # Look for container ID in cgroup (format: 0::/../CONTAINERID)
                    if '/../' in content:
                        # Extract full container ID after /../
                        container_id = content.split('/../')[1].strip()
                        if len(container_id) == 64:  # Full container ID
                            if container_id not in container_id_to_pids:
                                container_id_to_pids[container_id] = []
                            container_id_to_pids[container_id].append(pid)
            except:
                pass
        
        debug_print(f"Mapped PIDs for {len(container_id_to_pids)} containers")
        
        container_info = {}
        for container in containers:
            info = container.attrs
            
            # Get PIDs from our fast scan (instead of container.top())
            pids = container_id_to_pids.get(container.id, [])
            
            debug_print(f"Container {container.name}: found {len(pids)} PIDs")
            
            # Get image size from API (fast!)
            image_size = 0
            try:
                image_size = container.image.attrs.get('Size', 0)
                debug_print(f"Container {container.name}: image size = {image_size} bytes ({image_size/1024/1024:.2f} MB)")
            except:
                pass
            
            container_info[container.name] = {
                'id': container.id,
                'name': container.name,
                'state': info.get('State', {}),
                'host_config': info.get('HostConfig', {}),
                'mounts': info.get('Mounts', []),
                'graph_driver': info.get('GraphDriver', {}),
                'image_size': image_size,
                'container_obj': container,
                'pids': pids  # Store PIDs for fast /proc access
            }
        
        return container_info, None
    except Exception as e:
        return None, f"Docker error: {e}"


# ============================================================================
# CPU METRICS from /proc (PRIMARY method)
# ============================================================================

@perf_track
def read_cpu_from_proc(pids):
    """
    Get CPU ticks from /proc (PRIMARY method for nested Docker).
    Returns total CPU ticks (utime + stime) for all container processes.
    """
    try:
        if not pids:
            return 0
        
        total_cpu_ticks = 0
        proc_base_used = None
        
        # Try both /proc and /host/proc
        for proc_base in ['/proc', '/host/proc']:
            if not os.path.exists(proc_base):
                continue
            
            temp_ticks = 0
            for pid in pids:
                stat_file = f'{proc_base}/{pid}/stat'
                try:
                    if not os.path.exists(stat_file):
                        continue
                    
                    with open(stat_file, 'r') as f:
                        line = f.read().strip()
                        
                        # Format: pid (name with spaces) state ppid ... utime stime ...
                        # Find last closing paren to handle process names with spaces
                        rparen_idx = line.rfind(')')
                        if rparen_idx == -1:
                            continue
                        
                        # Everything after ')' is space-separated fields
                        after_name = line[rparen_idx + 1:].strip().split()
                        
                        # Fields after name (0-indexed):
                        # 0: state, 1: ppid, 2: pgrp, 3: session, 4: tty_nr, 5: tpgid,
                        # 6: flags, 7: minflt, 8: cminflt, 9: majflt, 10: cmajflt,
                        # 11: utime, 12: stime
                        if len(after_name) >= 13:
                            utime = int(after_name[11])
                            stime = int(after_name[12])
                            temp_ticks += utime + stime
                
                except (FileNotFoundError, PermissionError, ValueError, IndexError):
                    continue
            
            if temp_ticks > 0:
                total_cpu_ticks = temp_ticks
                proc_base_used = proc_base
                break
        
        if proc_base_used:
            debug_print(f"CPU: Read {total_cpu_ticks} ticks from {proc_base_used}")
        
        return total_cpu_ticks
    except Exception:
        return 0


# ============================================================================
# MEMORY METRICS from /proc (PRIMARY method)
# ============================================================================

@perf_track
def read_memory_from_proc(pids):
    """Get memory from /proc (PRIMARY method for nested Docker)."""
    try:
        if not pids:
            return 0
        
        total_rss = 0
        
        # Try both /proc and /host/proc
        for proc_base in ['/proc', '/host/proc']:
            if not os.path.exists(proc_base):
                continue
            
            temp_rss = 0
            for pid in pids:
                status_file = f'{proc_base}/{pid}/status'
                try:
                    if not os.path.exists(status_file):
                        continue
                    
                    with open(status_file, 'r') as f:
                        for line in f:
                            if line.startswith('VmRSS:'):
                                kb = int(line.split()[1])
                                temp_rss += kb * 1024  # Convert to bytes
                                break
                except (FileNotFoundError, PermissionError, ValueError):
                    continue
            
            if temp_rss > 0:
                total_rss = temp_rss
                break
        
        return total_rss
    except Exception:
        return 0


@perf_track
def get_host_memory():
    """Get total host memory (checks /host/proc first for nested Docker in LXC)."""
    try:
        # Try /host/proc first (for nested Docker in LXC), then /proc (bare metal)
        for proc_base in ['/host/proc', '/proc']:
            meminfo_path = f'{proc_base}/meminfo'
            if not os.path.exists(meminfo_path):
                debug_print(f"Host memory: {meminfo_path} does not exist")
                continue
            
            with open(meminfo_path, 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        kb = int(line.split()[1])
                        mem_bytes = kb * 1024  # Convert to bytes
                        debug_print(f"Host memory: {mem_bytes} bytes ({mem_bytes/1024/1024/1024:.2f} GB) from {meminfo_path}")
                        return mem_bytes
        
        debug_print("Host memory: Could not read from any meminfo path")
        return 0
    except Exception as e:
        debug_print(f"Host memory: Exception - {e}")
        return 0


# Cache host memory (doesn't change)
HOST_MEMORY = get_host_memory()


@perf_track
def get_memory_limit(container_id, host_config):
    """Get memory limit - use host RAM if no limit set."""
    try:
        # Check if explicit limit is set in container config
        limit = host_config.get('Memory', 0)
        if limit > 0:
            debug_print(f"Memory limit from host_config: {limit} bytes")
            return limit
        
        # Try cgroups
        limit = read_cgroup_memory_limit(container_id)
        if limit > 0:
            debug_print(f"Memory limit from cgroups: {limit} bytes")
            return limit
        
        # No limit set - use host RAM
        debug_print(f"No memory limit set, using host RAM: {HOST_MEMORY} bytes")
        return HOST_MEMORY
    except Exception:
        return HOST_MEMORY


@perf_track
def read_cgroup_memory_limit(container_id):
    """Read memory limit from cgroups."""
    try:
        # Try cgroup v2
        paths = [
            f'/sys/fs/cgroup/docker/{container_id}/memory.max',
            f'/sys/fs/cgroup/docker/{container_id[:12]}/memory.max',
            # cgroup v1
            f'/sys/fs/cgroup/memory/docker/{container_id}/memory.limit_in_bytes',
            f'/sys/fs/cgroup/memory/docker/{container_id[:12]}/memory.limit_in_bytes',
        ]
        
        for path in paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    limit_str = f.read().strip()
                    if limit_str == 'max':
                        return 0
                    limit = int(limit_str)
                    if limit < 1e15:  # Ignore unreasonably large values
                        return limit
        
        return 0
    except Exception:
        return 0


# ============================================================================
# BLOCK I/O from cgroups
# ============================================================================

@perf_track
def read_cgroup_blkio(container_id):
    """Read block I/O from cgroups."""
    try:
        # Try cgroup v2
        paths = [
            f'/sys/fs/cgroup/docker/{container_id}/io.stat',
            f'/sys/fs/cgroup/docker/{container_id[:12]}/io.stat',
            # cgroup v1
            f'/sys/fs/cgroup/blkio/docker/{container_id}/blkio.throttle.io_service_bytes',
            f'/sys/fs/cgroup/blkio/docker/{container_id[:12]}/blkio.throttle.io_service_bytes',
        ]
        
        read_bytes = 0
        write_bytes = 0
        
        for path in paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    content = f.read()
                    
                    # cgroup v2 format: "8:0 rbytes=X wbytes=Y"
                    if 'rbytes' in content:
                        for line in content.split('\n'):
                            if 'rbytes' in line:
                                parts = line.split()
                                for part in parts:
                                    if part.startswith('rbytes='):
                                        read_bytes += int(part.split('=')[1])
                                    elif part.startswith('wbytes='):
                                        write_bytes += int(part.split('=')[1])
                    
                    # cgroup v1 format: "8:0 Read X" / "8:0 Write Y"
                    elif 'Read' in content or 'Write' in content:
                        for line in content.split('\n'):
                            parts = line.split()
                            if len(parts) >= 3:
                                if parts[1] == 'Read':
                                    read_bytes += int(parts[2])
                                elif parts[1] == 'Write':
                                    write_bytes += int(parts[2])
                
                return read_bytes, write_bytes
        
        return 0, 0
    except Exception:
        return 0, 0


@perf_track
def read_blkio_from_proc(pids):
    """
    Read Block I/O from /proc (PRIMARY method for nested Docker).
    Returns cumulative read_bytes and write_bytes for all container processes.
    """
    try:
        if not pids:
            return 0, 0
        
        total_read = 0
        total_write = 0
        
        # Try both /proc and /host/proc
        for proc_base in ['/proc', '/host/proc']:
            if not os.path.exists(proc_base):
                continue
            
            temp_read = 0
            temp_write = 0
            
            for pid in pids:
                io_file = f'{proc_base}/{pid}/io'
                try:
                    if not os.path.exists(io_file):
                        continue
                    
                    with open(io_file, 'r') as f:
                        for line in f:
                            # Format: "read_bytes: 1234567"
                            if line.startswith('read_bytes:'):
                                temp_read += int(line.split(':')[1].strip())
                            elif line.startswith('write_bytes:'):
                                temp_write += int(line.split(':')[1].strip())
                
                except (FileNotFoundError, PermissionError, ValueError):
                    continue
            
            if temp_read > 0 or temp_write > 0:
                total_read = temp_read
                total_write = temp_write
                debug_print(f"Block I/O from {proc_base}: read={total_read}, write={total_write}")
                break
        
        return total_read, total_write
    except Exception:
        return 0, 0


# ============================================================================
# NETWORK STATS from /proc
# ============================================================================

@perf_track
def read_network_stats(pids):
    """Read network stats from host /proc (requires pid: host)."""
    try:
        if not pids:
            return 0, 0
        
        # Use first PID to read network stats
        main_pid = pids[0]
        
        # Try both /proc and /host/proc
        for proc_base in ['/proc', '/host/proc']:
            net_dev_path = f'{proc_base}/{main_pid}/net/dev'
            
            if not os.path.exists(net_dev_path):
                continue
            
            try:
                with open(net_dev_path, 'r') as f:
                    content = f.read()
                
                rx_bytes = 0
                tx_bytes = 0
                
                for line in content.split('\n'):
                    # Skip header lines
                    if ':' not in line or 'Inter-' in line or 'face' in line:
                        continue
                    
                    # Format: "  eth0: 12345 123 ..."
                    parts = line.split()
                    if len(parts) >= 10:
                        # Skip loopback
                        if parts[0].startswith('lo'):
                            continue
                        
                        # RX bytes is column 1, TX bytes is column 9
                        rx_bytes += int(parts[1])
                        tx_bytes += int(parts[9])
                
                debug_print(f"Network from {proc_base}: rx={rx_bytes}, tx={tx_bytes}")
                return rx_bytes, tx_bytes
                
            except (IOError, ValueError):
                continue
        
        return 0, 0
        
    except Exception:
        return 0, 0


# ============================================================================
# VOLUME SIZE METRICS (optional, adds ~1s)
# ============================================================================


def match_container_volumes(mounts, volume_sizes):
    """
    Match container's mounts to volume sizes.
    Returns total size of all volumes used by container.
    """
    try:
        total_size = 0
        
        for mount in mounts:
            mount_type = mount.get('Type')
            
            # Only count named volumes (not bind mounts)
            if mount_type == 'volume':
                volume_name = mount.get('Name', '')
                if volume_name in volume_sizes:
                    total_size += volume_sizes[volume_name]
        
        return total_size
    except Exception:
        return 0


@perf_track
def get_all_volume_sizes():
    """
    Get sizes of all Docker named volumes with ONE du command.
    Sequential approach - gentler on CPU than parallel for monitoring workloads.
    Returns dict: {volume_name: size_bytes}
    """
    try:
        import subprocess
        
        glob_result = glob.glob('/var/lib/docker/volumes/*/_data')
        if not glob_result:
            debug_print("Volume sizes: No volumes found in /var/lib/docker/volumes")
            return {}
        
        debug_print(f"Volume sizes: Found {len(glob_result)} volume paths to measure")
        
        # Single sequential du - lower CPU impact for regular monitoring
        result = subprocess.run(
            ['du', '-sb'] + glob_result,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            debug_print(f"Volume sizes: du command failed with return code {result.returncode}")
            if result.stderr:
                debug_print(f"Volume sizes: stderr: {result.stderr}")
            return {}
        
        volume_sizes = {}
        lines = result.stdout.strip().split('\n')
        
        debug_print(f"Volume sizes: Processing {len(lines)} output lines from du")
        
        for line in lines:
            if not line:
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            size = int(parts[0])
            path = parts[1]
            
            # Extract volume name from path: /var/lib/docker/volumes/root_traefik_data/_data
            # Volume name is between 'volumes/' and '/_data'
            if '/volumes/' in path and '/_data' in path:
                volume_name = path.split('/volumes/')[1].split('/_data')[0]
                volume_sizes[volume_name] = size
                debug_print(f"Volume '{volume_name}': {size} bytes ({size/1024/1024:.2f} MB)")
        
        debug_print(f"Volume sizes: Total {len(volume_sizes)} volumes measured")
        return volume_sizes
    except Exception as e:
        debug_print(f"Volume sizes: Exception - {e}")
        return {}


@perf_track
def calculate_container_volume_total(mounts, volume_sizes):
    """
    Calculate total size of all named volumes for a container.
    Only counts volumes, not bind mounts.
    Matches by Source path to handle prefix mismatches (e.g., ts_data vs root_ts_data).
    """
    try:
        total = 0
        matched_volumes = []
        
        for mount in mounts:
            mount_type = mount.get('Type')
            
            # Only count named volumes, not bind mounts
            if mount_type == 'volume':
                # Get the actual source path, e.g., /var/lib/docker/volumes/root_ts_data/_data
                source = mount.get('Source', '')
                
                if source and '/volumes/' in source:
                    # Extract volume name from path: /var/lib/docker/volumes/root_ts_data/_data
                    volume_name_from_path = source.split('/volumes/')[1].split('/_data')[0]
                    
                    if volume_name_from_path in volume_sizes:
                        vol_size = volume_sizes[volume_name_from_path]
                        total += vol_size
                        matched_volumes.append(f"{volume_name_from_path}={vol_size}")
        
        if matched_volumes:
            debug_print(f"Container volumes: {', '.join(matched_volumes)} | Total: {total} bytes")
        
        return total
    except Exception:
        return 0


# ============================================================================
# CONTAINER SIZE METRICS (fast, adds ~65ms)
# ============================================================================

@perf_track
def get_all_container_sizes(container_info):
    """
    Get writable layer (UpperDir) sizes for all containers with ONE du command.
    Fast approach (~65ms for 22 containers).
    Returns dict: {container_name: size_bytes}
    """
    try:
        import subprocess
        
        # Collect all UpperDir paths
        upper_dirs = {}  # {path: container_name}
        for container_name, info in container_info.items():
            graph_driver = info.get('graph_driver', {})
            upper_dir = graph_driver.get('Data', {}).get('UpperDir')
            
            if upper_dir and os.path.exists(upper_dir):
                upper_dirs[upper_dir] = container_name
        
        if not upper_dirs:
            debug_print("Container sizes: No UpperDir paths found")
            return {}
        
        debug_print(f"Container sizes: Found {len(upper_dirs)} UpperDir paths")
        
        # Single du command for all containers
        result = subprocess.run(
            ['du', '-sb'] + list(upper_dirs.keys()),
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            debug_print(f"Container sizes: du failed with return code {result.returncode}")
            return {}
        
        container_sizes = {}
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            size = int(parts[0])
            path = parts[1]
            
            if path in upper_dirs:
                container_name = upper_dirs[path]
                container_sizes[container_name] = size
                debug_print(f"Container '{container_name}' UpperDir: {size} bytes ({size/1024/1024:.2f} MB)")
        
        return container_sizes
    except Exception as e:
        debug_print(f"Container sizes: Exception - {e}")
        return {}


# ============================================================================
# LOG FILE SIZE
# ============================================================================

@perf_track
def get_log_size(container_id):
    """Get log file size for a container."""
    try:
        # Docker log file path
        log_paths = [
            f'/var/lib/docker/containers/{container_id}/{container_id}-json.log',
            f'/var/lib/docker/containers/{container_id[:12]}/{container_id[:12]}-json.log',
        ]
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                size = os.path.getsize(log_path)
                debug_print(f"Log file: {log_path} = {size} bytes ({size/1024/1024:.2f} MB)")
                return size
        
        return 0
    except Exception:
        return 0


# ============================================================================
# HEALTH, UPTIME, RESTART
# ============================================================================

def get_health_status(state):
    """Extract health status from container state."""
    try:
        is_running = state.get('Running', False)
        
        health = state.get('Health', {})
        if health:
            status = health.get('Status', 'none')
            if status == 'healthy':
                return 1
            elif status in ['unhealthy', 'starting']:
                return 0
            else:
                return -1
        else:
            # No healthcheck - use running state
            return 1 if is_running else 0
    except Exception:
        return -1


def get_uptime(state):
    """Calculate container uptime from state."""
    try:
        started_at_str = state.get('StartedAt')
        if not started_at_str:
            return 0
        
        if '.' in started_at_str:
            started_at_str = started_at_str.split('.')[0] + 'Z'
        
        started_at = datetime.fromisoformat(started_at_str.replace('Z', '+00:00'))
        now = datetime.now(started_at.tzinfo)
        return int((now - started_at).total_seconds())
    except Exception:
        return 0


def get_restart_count(state):
    """Get restart count from state."""
    return state.get('RestartCount', 0)


# ============================================================================
# COLLECT ALL METRICS
# ============================================================================

@perf_track
def collect_container_metrics(container_info, verbose=False):
    """
    Collect all metrics for all containers.
    
    Process:
    1. Take CPU measurement #1 (or use cache from last run ~60s ago)
    2. Take Network measurement #1 (or use cache from last run)
    3. Measure volumes (~750ms) and containers (~65ms) - happens DURING measurement window
    4. For each container: collect memory, block I/O, disk, logs, health, uptime, restarts
    5. Take CPU measurement #2, calculate CPU% from delta over time
    6. Take Network measurement #2, calculate bytes/sec from delta
    7. Save CPU and Network measurements to cache for next run
    
    Returns: dict of {container_name: metrics}
    """
    all_metrics = {}
    
    # START CPU MEASUREMENT IMMEDIATELY (BEFORE heavy volume scan!)
    cpu_measurements_1 = {}
    network_measurements_1 = {}
    has_cpu_cache = True
    has_network_cache = True
    
    for container_name, info in container_info.items():
        pids = info['pids']
        
        # Check CPU cache
        cached_ticks, cached_time = get_cached_cpu(container_name)
        
        if cached_ticks is not None:
            # Use cache as baseline (from previous run ~60s ago)
            cpu_measurements_1[container_name] = (cached_ticks, cached_time)
        else:
            # Take first measurement NOW
            cpu_measurements_1[container_name] = (read_cpu_from_proc(pids), time.time())
            has_cpu_cache = False
        
        # Check Network cache
        cached_rx, cached_tx, cached_net_time = get_cached_network(container_name)
        
        if cached_rx is not None:
            # Use cache as baseline
            network_measurements_1[container_name] = (cached_rx, cached_tx, cached_net_time)
        else:
            # Take first measurement NOW
            rx, tx = read_network_stats(pids)
            network_measurements_1[container_name] = (rx, tx, time.time())
            has_network_cache = False
    
    if verbose:
        if has_cpu_cache:
            print(f"  CPU: Using cache (no sleep needed)", file=sys.stderr)
        else:
            print(f"  CPU: First run - measuring during work", file=sys.stderr)
        if has_network_cache:
            print(f"  Network: Using cache for rate calculation", file=sys.stderr)
        else:
            print(f"  Network: First run - measuring during work", file=sys.stderr)
    
    # NOW get all volume sizes and container sizes (happens DURING CPU/Network measurement window)
    if verbose:
        print(f"  Measuring all volume sizes (this takes ~750ms)...", file=sys.stderr)
    volume_sizes = get_all_volume_sizes()
    if verbose:
        print(f"  Found {len(volume_sizes)} volumes", file=sys.stderr)
    
    if verbose:
        print(f"  Measuring container writable layers (this takes ~65ms)...", file=sys.stderr)
    container_data_sizes = get_all_container_sizes(container_info)
    if verbose:
        print(f"  Found {len(container_data_sizes)} container data sizes", file=sys.stderr)
    
    # DO ALL OTHER WORK (continues during CPU/Network measurement window)
    for container_name, info in container_info.items():
        if verbose:
            print(f"  Collecting: {container_name}...", file=sys.stderr, end='')
        
        if debug_enabled:
            debug_print(f"\n{'='*70}")
            debug_print(f"COLLECTING METRICS FOR: {container_name}")
            debug_print(f"{'='*70}")
        
        container_start = time.time()
        
        container_id = info['id']
        state = info['state']
        host_config = info['host_config']
        mounts = info['mounts']
        pids = info['pids']
        
        # Memory
        mem_usage = read_memory_from_proc(pids)
        mem_limit = get_memory_limit(container_id, host_config)
        mem_percent = round((mem_usage / mem_limit * 100), 2) if mem_limit > 0 else 0
        
        debug_print(f"Memory: usage={mem_usage} bytes, limit={mem_limit} bytes, percent={mem_percent}%")
        
        # Block I/O (try /proc first, fallback to cgroups)
        read_bytes, write_bytes = read_blkio_from_proc(pids)
        if read_bytes == 0 and write_bytes == 0:
            # Fallback to cgroups if /proc didn't work
            debug_print("Block I/O: /proc returned zeros, trying cgroups fallback")
            read_bytes, write_bytes = read_cgroup_blkio(container_id)
            if read_bytes > 0 or write_bytes > 0:
                debug_print(f"Block I/O from cgroups: read={read_bytes}, write={write_bytes}")
        
        # Disk sizes
        volume_total = calculate_container_volume_total(mounts, volume_sizes)
        container_data_size = container_data_sizes.get(container_name, 0)
        # Container = Image size (from API) + UpperDir (writable layer)
        image_size = info.get('image_size', 0)
        container_size = image_size + container_data_size
        
        debug_print(f"Disk: image={image_size}, data={container_data_size}, container_total={container_size}, volumes={volume_total}")
        
        log_size = get_log_size(container_id)
        
        # Calculate total disk usage
        disk_total = container_size + volume_total + log_size
        
        debug_print(f"Disk TOTAL: {disk_total} bytes ({disk_total/1024/1024:.2f} MB)")
        
        health_status = get_health_status(state)
        uptime_seconds = get_uptime(state)
        restart_count = get_restart_count(state)
        
        all_metrics[container_name] = {
            'health_status': health_status,
            'cpu_percent': 0.0,  # Calculated next
            'memory_usage': mem_usage,
            'memory_percent': mem_percent,
            'network_rx_rate': 0.0,  # Calculated next
            'network_tx_rate': 0.0,  # Calculated next
            'block_io_read': read_bytes,
            'block_io_write': write_bytes,
            'disk_container_data': container_data_size,
            'disk_container': container_size,
            'disk_volumes': volume_total,
            'disk_total': disk_total,
            'log_size': log_size,
            'uptime_seconds': uptime_seconds,
            'restart_count': restart_count,
            'pids': pids
        }
        
        container_duration = (time.time() - container_start) * 1000
        
        if verbose:
            print(f" {container_duration:.0f}ms", file=sys.stderr)
    
    # TAKE SECOND MEASUREMENTS and calculate CPU + Network rates
    for container_name, metrics in all_metrics.items():
        pids = metrics['pids']
        current_time = time.time()
        
        # CPU calculation
        current_ticks = read_cpu_from_proc(pids)
        ticks_1, time_1 = cpu_measurements_1[container_name]
        tick_delta = current_ticks - ticks_1
        time_delta = current_time - time_1
        
        if time_delta > 0 and tick_delta >= 0:
            cpu_seconds = tick_delta * 0.01  # USER_HZ = 100
            cpu_percent = round((cpu_seconds / time_delta) * 100.0, 2)
        else:
            cpu_percent = 0.0
        
        metrics['cpu_percent'] = cpu_percent
        
        # Save CPU to cache
        save_cpu_cache(container_name, current_ticks)
        
        # Network rate calculation
        current_rx, current_tx = read_network_stats(pids)
        rx_1, tx_1, net_time_1 = network_measurements_1[container_name]
        net_time_delta = current_time - net_time_1
        
        if net_time_delta > 0:
            rx_delta = current_rx - rx_1
            tx_delta = current_tx - tx_1
            
            # Handle counter reset (container restart)
            if rx_delta < 0:
                rx_delta = current_rx
            if tx_delta < 0:
                tx_delta = current_tx
            
            rx_rate = rx_delta / net_time_delta  # bytes/sec
            tx_rate = tx_delta / net_time_delta  # bytes/sec
        else:
            rx_rate = 0.0
            tx_rate = 0.0
        
        metrics['network_rx_rate'] = rx_rate
        metrics['network_tx_rate'] = tx_rate
        
        # Save Network to cache
        save_network_cache(container_name, current_rx, current_tx)
        
        # Remove temporary pids
        del metrics['pids']
        
        if verbose:
            print(f"    {container_name}: CPU {cpu_percent}% | Net RX {rx_rate:.1f} B/s TX {tx_rate:.1f} B/s", file=sys.stderr)
    
    return all_metrics


# ============================================================================
# PERFORMANCE REPORT
# ============================================================================

def print_performance_report(resource_stats=None):
    """Print detailed performance breakdown."""
    total = sum(perf_timings.values())
    
    print("\n" + "="*70, file=sys.stderr)
    print(f"PERFORMANCE REPORT - Total: {total:.2f}ms", file=sys.stderr)
    print("="*70, file=sys.stderr)
    
    sorted_timings = sorted(perf_timings.items(), key=lambda x: x[1], reverse=True)
    
    for func_name, duration in sorted_timings:
        percentage = (duration / total * 100) if total > 0 else 0
        print(f"{func_name:40s} {duration:8.2f}ms ({percentage:5.1f}%)", file=sys.stderr)
    
    print("="*70, file=sys.stderr)
    
    # Add resource usage if available
    if resource_stats:
        print("\nRESOURCE USAGE (Script Impact):", file=sys.stderr)
        print("="*70, file=sys.stderr)
        print(f"Wall time:      {resource_stats['wall_time_ms']:8.1f}ms", file=sys.stderr)
        print(f"CPU time:       {resource_stats['cpu_time_ms']:8.1f}ms ({resource_stats['cpu_percent']:.1f}% of 1 core)", file=sys.stderr)
        print(f"Peak memory:    {resource_stats['peak_mem_mb']:8.2f}MB", file=sys.stderr)
        print(f"Final memory:   {resource_stats['final_mem_mb']:8.2f}MB", file=sys.stderr)
        print("="*70, file=sys.stderr)
        
        # Impact assessment
        if resource_stats['cpu_percent'] < 50:
            impact = "LOW - Safe for real-time applications ✓"
        elif resource_stats['cpu_percent'] < 100:
            impact = "MEDIUM - Monitor during peak load"
        else:
            impact = "HIGH - May impact real-time applications"
        print(f"Impact: {impact}", file=sys.stderr)
        print("="*70, file=sys.stderr)


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main execution - collect all containers and write to shm."""
    global perf_tracking_enabled, debug_enabled
    
    script_start = time.time()
    
    # Parse arguments
    show_perf = '--perf' in sys.argv
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    debug_enabled = '--debug' in sys.argv
    
    # Enable performance tracking
    perf_tracking_enabled = show_perf
    
    # Initialize resource tracker if performance monitoring requested
    resource_tracker = ResourceTracker() if show_perf else None
    
    # Get all container info (single docker inspect call)
    print("Fetching container info...", file=sys.stderr)
    container_info, error = get_all_container_info()
    if resource_tracker:
        resource_tracker.update_peak_mem()
    
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    
    if not container_info:
        print("No running containers found", file=sys.stderr)
        return 1
    
    print(f"Found {len(container_info)} containers", file=sys.stderr)
    
    # Collect metrics for all containers
    all_metrics = collect_container_metrics(container_info, verbose)
    if resource_tracker:
        resource_tracker.update_peak_mem()
    
    # Save all metrics to cache
    print(f"Saving metrics to shm ({METRICS_CACHE_DIR})...", file=sys.stderr)
    save_all_metrics_cache(all_metrics)
    print(f"Wrote {len(all_metrics)} containers to shm", file=sys.stderr)
    
    total_duration = (time.time() - script_start) * 1000
    avg_duration = total_duration / len(all_metrics) if len(all_metrics) > 0 else 0
    
    # Debug output to stderr
    print(f"\n{'='*70}", file=sys.stderr)
    print(f"COLLECTION SUMMARY", file=sys.stderr)
    print(f"{'='*70}", file=sys.stderr)
    print(f"Total containers: {len(all_metrics)}", file=sys.stderr)
    print(f"Total time: {total_duration:.0f}ms", file=sys.stderr)
    print(f"Avg per container: {avg_duration:.1f}ms", file=sys.stderr)
    print(f"Cache location: {METRICS_CACHE_DIR}", file=sys.stderr)
    print(f"{'='*70}", file=sys.stderr)
    
    if show_perf and resource_tracker:
        resource_stats = resource_tracker.get_stats()
        print_performance_report(resource_stats)
    
    # PRTG Script V2 JSON output to stdout
    prtg_response = {
        "version": 2,
        "status": "ok",
        "message": f"Poll: {len(all_metrics)} containers | {total_duration:.0f}ms total",
        "channels": [
            {
                "id": 10,
                "name": "Containers Monitored",
                "type": "integer",
                "value": len(all_metrics),
                "kind": "count"
            },
            {
                "id": 11,
                "name": "Collection Time",
                "type": "integer",
                "value": int(total_duration),
                "kind": "time_milliseconds"
            },
            {
                "id": 12,
                "name": "Avg Time per Container",
                "type": "integer",
                "value": int(avg_duration),
                "kind": "time_milliseconds"
            }
        ]
    }
    
    print(json.dumps(prtg_response, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(json.dumps({
            "version": 2,
            "status": "error",
            "message": f"Unexpected error: {e}"
        }), file=sys.stderr)
        sys.exit(1)