#!/usr/bin/env python3
"""
PRTG Docker Container Stats - SENSOR SCRIPT FOR SCRIPT V2 (Read from SHM)
Version: 3.2.0

READ-ONLY SENSOR SCRIPT for Script V2 sensors:
- Reads metrics from shared memory (written by docker_stats.py)
- Outputs Script V2 JSON format directly
- Fast lookup: ~1-2ms (just file read + JSON parse)
- No Docker API calls, no process scanning, no collection

Usage:
    python3 docker_stats_reader.py --container teamspeak
    
Returns:
    Script V2 JSON format
"""

import sys
import json
import os
import time
import argparse
import shlex

VERSION = "3.2.0"

# Cache configuration
METRICS_CACHE_DIR = "/dev/shm/prtg_docker_metrics"
METRICS_CACHE_TTL = 1800  # 30 minutes in seconds


def fail(message: str):
    """Output error as JSON and exit."""
    error_response = {
        "version": 2,
        "status": "error",
        "message": message
    }
    print(json.dumps(error_response))
    exit(0)


def get_metrics_cache_file(container_name):
    """Get metrics cache file path for a container."""
    return os.path.join(METRICS_CACHE_DIR, f"{container_name}.json")


def get_cached_metrics(container_name, max_age=METRICS_CACHE_TTL):
    """
    Get cached metrics for a container as Script V2 JSON.
    Returns Script V2 JSON dict.
    """
    cache_file = get_metrics_cache_file(container_name)
    
    if not os.path.exists(cache_file):
        return {
            "version": 2,
            "status": "error",
            "message": f"No cached data found for container '{container_name}'. Cache file not found."
        }
    
    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
        
        timestamp = cache_data.get('timestamp', 0)
        cache_age = time.time() - timestamp
        
        # Check if cache is still valid
        if cache_age > max_age:
            return {
                "version": 2,
                "status": "error",
                "message": f"Cache expired for '{container_name}' (age: {cache_age:.1f}s, max: {max_age}s)"
            }
        
        # Get the Script V2 format data from cache
        script_v2_json = cache_data.get('script_v2_json')
        if not script_v2_json:
            return {
                "version": 2,
                "status": "error",
                "message": f"Invalid cache data for '{container_name}': missing script_v2_json"
            }
        
        # Enhance the message with cache info
        original_message = script_v2_json.get('message', '')
        enhanced_message = f"{original_message} | Cache: {cache_age:.1f}s"
        
        # Return Script V2 JSON with enhanced message
        result = script_v2_json.copy()
        result['message'] = enhanced_message
        return result
        
    except json.JSONDecodeError as e:
        return {
            "version": 2,
            "status": "error",
            "message": f"Invalid JSON in cache file for '{container_name}': {e}"
        }
    except Exception as e:
        return {
            "version": 2,
            "status": "error",
            "message": f"Error reading cache for '{container_name}': {e}"
        }


def setup():
    """Parse arguments from stdin (piped) or CLI (interactive)."""
    argparser = argparse.ArgumentParser(
        description="Docker stats reader for PRTG Script V2 sensor",
        exit_on_error=False,
    )
    
    argparser.add_argument(
        "--container",
        required=True,
        help="Container name to read stats for"
    )
    
    try:
        # Check if stdin is a tty (interactive) or piped from PRTG
        if sys.stdin.isatty():
            # Interactive mode - parse command line args
            args = argparser.parse_args()
        else:
            # PRTG mode - read from stdin (pipe)
            pipestring = sys.stdin.read().rstrip()
            args = argparser.parse_args(shlex.split(pipestring))
    except argparse.ArgumentError as e:
        fail(f"Could not parse input parameters: {e}")
    
    return args


def main():
    """Main execution - read container metrics and output Script V2 JSON."""
    
    try:
        # Parse arguments
        args = setup()
        
        if not args.container:
            fail("Container name not specified. Use: --container <container_name>")
        
        # Get cached metrics
        result = get_cached_metrics(args.container)
        
        # Output Script V2 JSON
        print(json.dumps(result))
        
        return 0
        
    except Exception as e:
        fail(f"Unexpected error: {e}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        fail(f"Fatal error: {e}")