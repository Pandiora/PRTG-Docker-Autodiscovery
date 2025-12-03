#!/usr/bin/env python3
"""
PRTG Docker Monitoring Setup Script - Script V2 Version
Version: 11.3.1 - Fixed race condition in limit configuration

New features:
- Cache validation for probe-id and probe-device-id
- Automatic probe device detection
- Docker Stats Writer sensor on probe device
- Cleanup orphaned sensors with --cleanup-orphaned flag
- Smart channel limits configuration (checks primary channel to avoid race condition)
- Primary channel set to Health Status (using undocumented editsettings endpoint)

Bug fix: Check primary channel instead of limitmode to ensure channels exist before
         declaring configuration complete. Prevents race condition on first run.
"""

import os
import sys

# Auto-elevate to root if needed
if os.geteuid() != 0:
    import subprocess
    print("Not running as root, re-executing with sudo...", file=sys.stderr)
    args = ['sudo', '-E', sys.executable] + sys.argv
    os.execvp('sudo', args)

import json
import time
import re
import socket
import requests
import urllib3
import docker
import argparse
from typing import Dict, List, Optional, Callable

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
PRTG_HOST = os.getenv('PRTG_HOST')
USERNAME = os.getenv('PRTG_USERNAME')
PASSWORD = os.getenv('PRTG_PASSWORD')

DEVICE_NAME = "Docker Containers"
SCRIPT_FILE = "docker_stats_reader.py"
WRITER_SCRIPT = "docker_stats_writer.py"
VERSION = "11.3.1"

# Cache files
PROBE_ID_CACHE_FILE = "/config/probe-id.txt"
PROBE_DEVICE_ID_CACHE_FILE = "/config/probe-device-id.txt"


class PRTGAPIv1:
    """PRTG API v1 wrapper for all operations."""
    
    def __init__(self, host: str, username: str, password: str):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.passhash = None
        self.session = requests.Session()
        self.session.verify = False
        
    def authenticate(self) -> bool:
        """Get passhash for authentication."""
        try:
            url = f"{self.host}/api/getpasshash.htm"
            params = {
                'username': self.username,
                'password': self.password
            }
            resp = self.session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            self.passhash = resp.text.strip()
            print(f"✓ Authenticated (passhash: {self.passhash[:10]}...)", file=sys.stderr)
            return True
        except Exception as e:
            print(f"✗ Authentication failed: {e}", file=sys.stderr)
            return False
    
    def _api_request(self, endpoint: str, params: Dict = None) -> Dict:
        """Make an API request with authentication."""
        if not self.passhash:
            raise RuntimeError("Not authenticated")
        
        url = f"{self.host}/api/{endpoint}"
        request_params = params or {}
        request_params.update({
            'username': self.username,
            'passhash': self.passhash
        })
        
        resp = self.session.get(url, params=request_params, timeout=30)
        resp.raise_for_status()
        
        # Handle JSON responses
        if endpoint.endswith('.json'):
            return resp.json()
        return {'text': resp.text.strip()}
    
    def probe_exists(self, probe_id: int) -> bool:
        """Check if probe exists."""
        try:
            params = {
                'content': 'probes',
                'columns': 'objid',
                'filter_objid': probe_id
            }
            result = self._api_request('table.json', params)
            return len(result.get('probes', [])) > 0
        except:
            return False
    
    def device_exists_simple(self, device_id: int) -> bool:
        """Check if device exists by ID."""
        try:
            params = {
                'content': 'devices',
                'columns': 'objid',
                'filter_objid': device_id
            }
            result = self._api_request('table.json', params)
            return len(result.get('devices', [])) > 0
        except:
            return False
    
    def validate_cached_id(self, cache_file: str, validation_func: Callable[[int], bool]) -> Optional[int]:
        """
        Returns cached ID if valid, None if invalid/missing.
        Deletes stale cache if validation fails.
        """
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cached_id = int(f.read().strip())
                
                if validation_func(cached_id):
                    return cached_id
                else:
                    # Stale cache - delete it
                    os.remove(cache_file)
                    print(f"  ✗ Cached ID {cached_id} no longer exists, invalidated cache", file=sys.stderr)
            except:
                pass
        return None
    
    def cache_id(self, cache_file: str, obj_id: int):
        """Cache an ID to file."""
        try:
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            with open(cache_file, 'w') as f:
                f.write(str(obj_id))
            print(f"  ✓ Cached ID {obj_id} to {cache_file}", file=sys.stderr)
        except Exception as e:
            print(f"  ⚠ Failed to cache ID: {e}", file=sys.stderr)
    
    def get_probe_by_hostname(self) -> Optional[int]:
        """Find probe ID matching multi-platform-probe@<hostname>."""
        # Validate cache first
        probe_id = self.validate_cached_id(PROBE_ID_CACHE_FILE, self.probe_exists)
        if probe_id:
            print(f"  ✓ Using cached probe ID: {probe_id}", file=sys.stderr)
            return probe_id
        
        # Get system hostname
        hostname = socket.gethostname()
        expected_probe_name = f"multi-platform-probe@{hostname}"
        print(f"  Looking for probe: {expected_probe_name}", file=sys.stderr)
        
        # Get all probes
        result = self._api_request('table.json', {
            'content': 'probes',
            'columns': 'objid,probe,name,status'
        })
        
        probes = result.get('probes', [])
        
        # Find probe matching the pattern
        for probe in probes:
            probe_name = probe.get('probe', '')
            if probe_name.startswith('multi-platform-probe@') and hostname in probe_name:
                probe_id = probe.get('objid')
                print(f"  ✓ Found probe: {probe_name} (ID: {probe_id})", file=sys.stderr)
                self.cache_id(PROBE_ID_CACHE_FILE, probe_id)
                return probe_id
        
        print(f"  ✗ Probe '{expected_probe_name}' not found", file=sys.stderr)
        return None
    
    def get_probe_device(self, probe_id: int) -> Optional[int]:
        """
        Get the probe's own device (where probe itself is monitored).
        The probe device is the first device under the probe.
        """
        # Validate cache first
        device_id = self.validate_cached_id(PROBE_DEVICE_ID_CACHE_FILE, self.device_exists_simple)
        if device_id:
            print(f"  ✓ Using cached probe device ID: {device_id}", file=sys.stderr)
            return device_id
        
        print(f"  Looking for probe device under probe {probe_id}...", file=sys.stderr)
        
        params = {
            'content': 'devices',
            'columns': 'objid,device,host',
            'filter_parentid': probe_id,
            'sortby': 'objid',  # Get oldest/first device
            'count': 1
        }
        
        result = self._api_request('table.json', params)
        devices = result.get('devices', [])
        
        if devices:
            device_id = devices[0]['objid']
            device_name = devices[0].get('device', '')
            print(f"  ✓ Found probe device: {device_name} (ID: {device_id})", file=sys.stderr)
            self.cache_id(PROBE_DEVICE_ID_CACHE_FILE, device_id)
            return device_id
        
        print(f"  ✗ No devices found under probe", file=sys.stderr)
        return None
    
    def device_exists(self, device_name: str, probe_id: int) -> Optional[int]:
        """Check if device exists on the probe."""
        params = {
            'content': 'devices',
            'columns': 'objid,device',
            'filter_parentid': probe_id,
            'filter_device': device_name
        }
        
        result = self._api_request('table.json', params)
        devices = result.get('devices', [])
        
        if devices:
            for device in devices:
                if device.get('device') == device_name:
                    return device['objid']
        return None
    
    def create_device(self, device_name: str, probe_id: int, host: str = '127.0.0.1') -> Optional[int]:
        """Create a new device using the PrtgAPI approach."""
        
        print(f"  Creating device '{device_name}' on probe {probe_id}...", file=sys.stderr)
        
        # Step 1: Check if device already exists
        existing_id = self.device_exists(device_name, probe_id)
        if existing_id:
            print(f"  ✓ Device already exists (ID: {existing_id})", file=sys.stderr)
            return existing_id
        
        # Step 2: Create device using adddevice2.htm
        url = f"{self.host}/adddevice2.htm"
        params = {
            'name_': device_name,
            'host_': host,
            'ipversion_': '0',
            'discoverytype_': '0',
            'discoveryschedule_': '0',
            'id': probe_id,
            'username': self.username,
            'passhash': self.passhash
        }
        
        try:
            resp = self.session.get(url, params=params, timeout=30)
            time.sleep(3)
            
            # Verify device was created
            device_id = self.device_exists(device_name, probe_id)
            if device_id:
                print(f"  ✓ Device created successfully (ID: {device_id})", file=sys.stderr)
                return device_id
            else:
                print(f"  ✗ Device not found after creation attempt", file=sys.stderr)
                return None
                
        except Exception as e:
            print(f"  ✗ Failed to create device: {e}", file=sys.stderr)
            return None
    
    def get_sensors(self, device_id: int) -> List[Dict]:
        """Get all sensors for a device."""
        params = {
            'content': 'sensors',
            'columns': 'objid,sensor,type,status,message,tags',
            'filter_parentid': device_id
        }
        
        result = self._api_request('table.json', params)
        return result.get('sensors', [])
    
    def create_writer_sensor_if_missing(self, device_id: int) -> bool:
        """Create Docker Stats Writer sensor on probe device if it doesn't exist."""
        sensor_name = "Docker Stats Writer"
        
        # Check if sensor already exists
        sensors = self.get_sensors(device_id)
        for sensor in sensors:
            if sensor.get('sensor') == sensor_name:
                print(f"  ✓ Writer sensor already exists (ID: {sensor['objid']})", file=sys.stderr)
                return True
        
        print(f"  Creating writer sensor '{sensor_name}'...", file=sys.stderr)
        
        try:
            # Get CSRF token
            token_url = f"{self.host}/controls/addsensor2.htm"
            params = {
                'id': device_id,
                'sensortype': 'paessler.exe.exe_sensor',
                'username': self.username,
                'passhash': self.passhash
            }
            
            resp = self.session.get(token_url, params=params, verify=False, timeout=30)
            resp.raise_for_status()
            
            csrf_token = None
            csrf_match = re.search(r'<input[^>]*name=["\']anti-csrf-token["\'][^>]*value=["\']([^"\']+)["\']', resp.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
            
            if not csrf_token:
                csrf_match = re.search(r'anti-csrf-token["\'\s]*[:=]["\'\s]*([a-zA-Z0-9%+=/_-]+)', resp.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
            
            # Create sensor
            create_url = f"{self.host}/addsensor5.htm"
            
            form_data = {
                'id': str(device_id),
                'tmpid': '10',
                'sensortype': 'paessler.exe.exe_sensor',
                'name_': sensor_name,
                'tags_': 'dockersensor scriptv2',
                'priority_': '3',
                'paessler-exe-exe_metascan_section-exe_metascan_group-exe_name_': WRITER_SCRIPT,
                'metascan_': '1',
                'metascan__check': WRITER_SCRIPT,
                'paessler-exe-exe_section-exe_group-parameters_': '',  # No parameters
                'paessler-exe-exe_section-exe_group-timeout_': '60',
                'writeresult_': 'DiscardResult',
                'intervalgroup': '1',
                'interval_': '60|60 seconds',  # 1 minute interval
                'errorintervalsdown_': '1',
                'inherittriggers': '1',
                'username': self.username,
                'passhash': self.passhash
            }
            
            if csrf_token:
                form_data['anti-csrf-token'] = csrf_token
            
            resp = self.session.post(create_url, data=form_data, verify=False, timeout=30)
            
            if resp.status_code in [200, 302]:
                time.sleep(2)
                
                # Verify
                sensors = self.get_sensors(device_id)
                for sensor in sensors:
                    if sensor.get('sensor') == sensor_name:
                        print(f"  ✓ Writer sensor created (ID: {sensor['objid']})", file=sys.stderr)
                        return True
                
                print(f"  ⚠ Writer sensor not found after creation", file=sys.stderr)
                return False
            else:
                print(f"  ✗ Failed to create writer sensor (status {resp.status_code})", file=sys.stderr)
                return False
                
        except Exception as e:
            print(f"  ✗ Error creating writer sensor: {e}", file=sys.stderr)
            return False
    
    def cleanup_orphaned_sensors(self, device_id: int, active_container_names: set) -> int:
        """Delete sensors for containers that no longer exist."""
        print(f"\n  Cleaning up orphaned sensors on device {device_id}...", file=sys.stderr)
        
        all_sensors = self.get_sensors(device_id)
        deleted_count = 0
        
        for sensor in all_sensors:
            sensor_name = sensor.get('sensor', '')
            sensor_id = sensor.get('objid')
            tags = sensor.get('tags', '').lower()
            
            # Safety check: only delete sensors with our tags
            if 'dockersensor' not in tags and 'scriptv2' not in tags:
                continue
            
            # Check if this sensor name matches an active container
            clean_name = sensor_name.replace("Docker: ", "")
            
            if clean_name not in active_container_names:
                # This sensor is orphaned - delete it
                try:
                    url = f"{self.host}/api/deleteobject.htm"
                    params = {
                        'id': sensor_id,
                        'approve': 1,
                        'username': self.username,
                        'passhash': self.passhash
                    }
                    self.session.get(url, params=params, timeout=30)
                    deleted_count += 1
                except:
                    pass  # Silent failure as requested
        
        return deleted_count
    
    def sensor_has_limits_configured(self, sensor_id: int) -> bool:
        """Check if sensor already has limits configured."""
        try:
            # Check if key channels have limitmode enabled
            url = f"{self.host}/api/getobjectproperty.htm"
            params = {
                'id': sensor_id,
                'name': 'channel(10,limitmode)',  # Health Status
                'username': self.username,
                'passhash': self.passhash
            }
            resp = self.session.get(url, params=params, timeout=10)
            # If limitmode is 1, limits are already configured
            return resp.text.strip() == '1'
        except:
            # If we can't check, assume not configured
            return False
    
    def set_primary_channel(self, sensor_id: int, channel_id: int = 10) -> bool:
        """
        Set the primary channel for a sensor using the editsettings endpoint.
        This is an undocumented/unofficial method that works.
        
        Args:
            sensor_id: The sensor ID
            channel_id: The channel ID to set as primary (default: 10 for Health Status)
        """
        try:
            url = f"{self.host}/editsettings"
            data = {
                'id': sensor_id,
                'primarychannel_': str(channel_id),
                'username': self.username,
                'passhash': self.passhash
            }
            
            resp = self.session.post(url, data=data, verify=False, timeout=10)
            if resp.status_code == 200:
                return True
            return False
        except:
            return False
    
    def needs_limit_configuration(self, sensor_id: int) -> bool:
        """
        Check if sensor needs limit configuration by checking the primary channel.
        
        We check primary channel (not limitmode) because:
        - Primary channel can only be set if channels actually exist
        - If primary channel == 10, we know full configuration succeeded
        - This avoids race condition where limitmode=1 but channels don't exist yet
        
        Returns True if limits not configured, False if already configured.
        """
        try:
            url = f"{self.host}/api/getobjectproperty.htm"
            params = {
                'id': sensor_id,
                'name': 'primarychannel',
                'show': 'nohtmlencode',
                'username': self.username,
                'passhash': self.passhash
            }
            resp = self.session.get(url, params=params, timeout=10)
            # If primary channel is already 10 (Health Status), configuration is done
            return resp.text.strip() != '10'
        except:
            # If check fails, attempt configuration anyway
            return True
    
    def configure_sensor_limits(self, sensor_id: int) -> bool:
        """
        Configure sensible channel limits for Docker container sensors.
        
        Channel limits:
        - 10: Health Status - Error if 0 (unhealthy) + SET AS PRIMARY
        - 11: CPU Usage - Warning 80%, Error 95%
        - 14: Memory Usage % - Warning 80%, Error 95%
        - 23: Log File Size - Warning 100MB, Error 500MB
        - 25: Restart Count - Warning 1, Error 5
        """
        try:
            url = f"{self.host}/api/setobjectproperty.htm"
            base_params = {
                'id': sensor_id,
                'username': self.username,
                'passhash': self.passhash
            }
            
            # Channel limit configurations - set limits FIRST, then enable limitmode
            limits = [
                # Health Status (10) - Error if value is 0 (unhealthy)
                ('10', 'limitminerror', '1'),  # Error if < 1
                ('10', 'limitmode', '1'),
                
                # CPU Usage (11) - Warning 80%, Error 95%
                ('11', 'limitmaxwarning', '80'),
                ('11', 'limitmaxerror', '95'),
                ('11', 'limitmode', '1'),
                
                # Memory Usage % (14) - Warning 80%, Error 95%
                ('14', 'limitmaxwarning', '80'),
                ('14', 'limitmaxerror', '95'),
                ('14', 'limitmode', '1'),
                
                # Log File Size (23) - Warning 100MB, Error 500MB
                ('23', 'limitmaxwarning', '104857600'),  # 100MB in bytes
                ('23', 'limitmaxerror', '524288000'),    # 500MB in bytes
                ('23', 'limitmode', '1'),
                
                # Restart Count (25) - Warning 1, Error 5
                ('25', 'limitmaxwarning', '1'),
                ('25', 'limitmaxerror', '5'),
                ('25', 'limitmode', '1'),
            ]
            
            # Apply each limit using correct subtype/subid syntax
            for channel_id, param_name, param_value in limits:
                params = base_params.copy()
                params['subtype'] = 'channel'
                params['subid'] = channel_id
                params['name'] = param_name
                params['value'] = param_value
                self.session.get(url, params=params, timeout=10)
            
            # Set primary channel to Health Status (channel 10) using editsettings
            if self.set_primary_channel(sensor_id, 10):
                print(f"    ✓ Configured limits + primary channel", file=sys.stderr)
            else:
                print(f"    ✓ Configured limits (primary channel failed)", file=sys.stderr)
            return True
            
        except Exception as e:
            print(f"    ⚠ Failed to configure limits: {e}", file=sys.stderr)
            return False
    
    def create_scriptv2_sensor(self, device_id: int, sensor_name: str, container_name: str) -> bool:
        """
        Create Script V2 sensor using parameters from PrtgAPI analysis.
        
        Based on PrtgAPI's DynamicSensorParameters output:
        - sensortype: paessler.exe.exe_sensor
        - metascan: 1
        - metascan__check: script file name
        - paessler-exe-exe_section-exe_group-parameters: script parameters
        - paessler-exe-exe_section-exe_group-timeout: timeout
        - writeresult: DiscardResult
        """
        
        try:
            # Step 1: Get CSRF token from addsensor2.htm
            token_url = f"{self.host}/controls/addsensor2.htm"
            params = {
                'id': device_id,
                'sensortype': 'paessler.exe.exe_sensor',  # Script V2 sensor type
                'username': self.username,
                'passhash': self.passhash
            }
            
            resp = self.session.get(token_url, params=params, verify=False, timeout=30)
            resp.raise_for_status()
            
            # Extract anti-csrf-token
            csrf_token = None
            
            # Try HTML input field first
            csrf_match = re.search(r'<input[^>]*name=["\']anti-csrf-token["\'][^>]*value=["\']([^"\']+)["\']', resp.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
            
            # Try JavaScript variable
            if not csrf_token:
                csrf_match = re.search(r'anti-csrf-token["\'\s]*[:=]["\'\s]*([a-zA-Z0-9%+=/_-]+)', resp.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
            
            if csrf_token:
                print(f"    ✓ Found CSRF token: {csrf_token[:20]}...", file=sys.stderr)
            else:
                print(f"    ⚠ No CSRF token found, attempting without", file=sys.stderr)
            
            # Step 2: Create the sensor using addsensor5.htm
            # Using Script V2 parameters as observed in PrtgAPI
            create_url = f"{self.host}/addsensor5.htm"
            
            form_data = {
                # Core parameters
                'id': str(device_id),
                'tmpid': '10',
                'sensortype': 'paessler.exe.exe_sensor',
                'name_': sensor_name,
                
                # Tags and priority
                'tags_': 'dockersensor scriptv2',
                'priority_': '3',
                
                # Script V2 specific parameters (EXACT match from PrtgAPI)
                'paessler-exe-exe_metascan_section-exe_metascan_group-exe_name_': SCRIPT_FILE,  # THE KEY PARAMETER!
                'metascan_': '1',
                'metascan__check': SCRIPT_FILE,
                'paessler-exe-exe_section-exe_group-parameters_': f'--container {container_name}',
                'paessler-exe-exe_section-exe_group-timeout_': '60',
                'writeresult_': 'DiscardResult',
                
                # Interval settings
                'intervalgroup': '1',
                'interval_': '60|60 seconds',
                'errorintervalsdown_': '1',
                
                # Triggers
                'inherittriggers': '1',
                
                # Authentication
                'username': self.username,
                'passhash': self.passhash
            }
            
            if csrf_token:
                form_data['anti-csrf-token'] = csrf_token
            
            # Debug: show what we're sending
            print(f"    Posting sensor creation with parameters:", file=sys.stderr)
            for key, value in form_data.items():
                if key not in ['username', 'passhash', 'anti-csrf-token']:
                    print(f"      {key} = {value}", file=sys.stderr)
            
            # Post the sensor creation
            resp = self.session.post(create_url, data=form_data, verify=False, timeout=30)
            
            print(f"    Response status: {resp.status_code}", file=sys.stderr)
            
            if resp.status_code in [200, 302]:
                # Wait for sensor to be created
                time.sleep(2)
                
                # Verify sensor exists
                sensors = self.get_sensors(device_id)
                for sensor in sensors:
                    if sensor.get('sensor') == sensor_name:
                        sensor_id = sensor.get('objid')
                        
                        # Trigger initial scan
                        try:
                            scan_url = f"{self.host}/api/scannow.htm"
                            scan_params = {
                                'id': sensor_id,
                                'username': self.username,
                                'passhash': self.passhash
                            }
                            self.session.get(scan_url, params=scan_params, timeout=10)
                            print(f"    ✓ Sensor created (ID: {sensor_id}) - scan triggered", file=sys.stderr)
                        except:
                            print(f"    ✓ Sensor created (ID: {sensor_id})", file=sys.stderr)
                        
                        return True
                
                print(f"    ⚠ Sensor not found after creation", file=sys.stderr)
                # Debug: show what sensors we found
                print(f"    Found {len(sensors)} sensors on device", file=sys.stderr)
                return False
            else:
                print(f"    ✗ POST failed with status {resp.status_code}", file=sys.stderr)
                # Debug: print response excerpt
                response_excerpt = resp.text[:1000] if len(resp.text) > 1000 else resp.text
                print(f"    Response excerpt: {response_excerpt}", file=sys.stderr)
                return False
            
        except Exception as e:
            print(f"    ✗ Error creating sensor: {e}", file=sys.stderr)
            import traceback
            print(f"    Traceback: {traceback.format_exc()}", file=sys.stderr)
            return False


def prtg_error(message: str):
    """Output PRTG-formatted error and exit."""
    print(json.dumps({"version": 2, "status": "error", "message": message}, indent=2))
    sys.exit(1)


def get_active_containers() -> List:
    """Get list of active Docker containers."""
    try:
        client = docker.from_env()
        containers = client.containers.list(filters={"status": "running"})
        print(f"✓ Found {len(containers)} active containers", file=sys.stderr)
        return containers
    except Exception as e:
        prtg_error(f"Failed to connect to Docker: {e}")


def main():
    """Main execution function."""
    # Parse arguments
    parser = argparse.ArgumentParser(description='PRTG Docker Monitoring Setup')
    parser.add_argument('--cleanup-orphaned', action='store_true',
                        help='Delete sensors for stopped containers')
    args = parser.parse_args()
    
    print("=" * 70, file=sys.stderr)
    print("DOCKER MONITORING SETUP (Script V2 Version)", file=sys.stderr)
    print(f"Version: {VERSION} - Fixed race condition + Primary channel", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    
    # Validate environment
    if not all([PRTG_HOST, USERNAME, PASSWORD]):
        prtg_error("Missing required environment variables (PRTG_HOST, PRTG_USERNAME, PRTG_PASSWORD)")
    
    # Initialize API
    api = PRTGAPIv1(PRTG_HOST, USERNAME, PASSWORD)
    
    print("\n[1/6] Authenticating...", file=sys.stderr)
    if not api.authenticate():
        prtg_error("Authentication failed")
    
    print("\n[2/6] Getting probe (with cache validation)...", file=sys.stderr)
    probe_id = api.get_probe_by_hostname()
    
    if not probe_id:
        prtg_error(f"Could not find probe matching hostname pattern 'multi-platform-probe@{socket.gethostname()}'")
    
    print(f"✓ Using probe ID: {probe_id}", file=sys.stderr)
    
    print("\n[3/6] Getting probe device (with cache validation)...", file=sys.stderr)
    probe_device_id = api.get_probe_device(probe_id)
    
    if not probe_device_id:
        prtg_error("Could not find probe device")
    
    print(f"✓ Using probe device ID: {probe_device_id}", file=sys.stderr)
    
    print("\n[4/6] Creating Docker Stats Writer sensor on probe device...", file=sys.stderr)
    api.create_writer_sensor_if_missing(probe_device_id)
    
    print("\n[5/6] Getting or creating Docker Containers device...", file=sys.stderr)
    containers_device_id = api.create_device(DEVICE_NAME, probe_id, '127.0.0.1')
    
    if not containers_device_id:
        prtg_error(f"Could not create or find device '{DEVICE_NAME}'")
    
    print(f"✓ Device: {DEVICE_NAME} (ID: {containers_device_id})", file=sys.stderr)
    
    print("\n[6/6] Discovering containers and creating sensors...", file=sys.stderr)
    containers = get_active_containers()
    if not containers:
        print(json.dumps({
            "version": 2, 
            "status": "ok", 
            "message": "No active containers found",
            "channels": [
                {"id": 10, "name": "Sensors Created", "type": "integer", "value": 0}
            ]
        }, indent=2))
        return
    
    # Sort containers by name for consistent processing order
    containers = sorted(containers, key=lambda c: c.name.lower())
    
    # Get existing sensors
    existing_sensors = {}
    all_sensors = api.get_sensors(containers_device_id)
    for sensor in all_sensors:
        name = sensor.get('sensor', '')
        # Match both old format ("Docker: name") and new format (just "name")
        for container in containers:
            if name == container.name or name == f"Docker: {container.name}":
                existing_sensors[container.name] = sensor['objid']
    
    print(f"✓ Found {len(existing_sensors)} existing container sensors", file=sys.stderr)
    
    created_count = 0
    existing_count = 0
    failed_count = 0
    
    # Process each container
    configured_count = 0
    for container in containers:
        container_name = container.name
        sensor_name = container_name  # NO "Docker: " prefix
        
        if container_name in existing_sensors:
            sensor_id = existing_sensors[container_name]
            print(f"  ✓ {sensor_name} exists (ID: {sensor_id})", file=sys.stderr)
            existing_count += 1
            
            # Check if limits need configuration
            if api.needs_limit_configuration(sensor_id):
                print(f"    Configuring limits for {sensor_name}...", file=sys.stderr)
                if api.configure_sensor_limits(sensor_id):
                    configured_count += 1
        else:
            print(f"  Creating {sensor_name}...", file=sys.stderr)
            
            # Create Script V2 sensor
            if api.create_scriptv2_sensor(containers_device_id, sensor_name, container_name):
                created_count += 1
                print(f"    ✓ Created successfully", file=sys.stderr)
                
                # Find the newly created sensor ID and configure limits
                time.sleep(1)
                sensors = api.get_sensors(containers_device_id)
                for sensor in sensors:
                    if sensor.get('sensor') == sensor_name:
                        sensor_id = sensor.get('objid')
                        # Configure limits on new sensor
                        if api.configure_sensor_limits(sensor_id):
                            configured_count += 1
                        break
            else:
                failed_count += 1
                print(f"    ✗ Failed to create", file=sys.stderr)
    
    # Report orphaned sensors
    active_container_names = {c.name for c in containers}
    orphaned = set(existing_sensors.keys()) - active_container_names
    deleted_count = 0
    
    if orphaned:
        print(f"\n⚠ Found {len(orphaned)} orphaned sensors for stopped containers:", file=sys.stderr)
        for name in orphaned:
            print(f"  - {name}", file=sys.stderr)
        
        # Cleanup if requested
        if args.cleanup_orphaned:
            deleted_count = api.cleanup_orphaned_sensors(containers_device_id, active_container_names)
            print(f"✓ Deleted {deleted_count} orphaned sensors", file=sys.stderr)
    
    print("\n" + "=" * 70, file=sys.stderr)
    print("SETUP COMPLETE", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"Created: {created_count}", file=sys.stderr)
    print(f"Existing: {existing_count}", file=sys.stderr)
    print(f"Configured: {configured_count}", file=sys.stderr)
    print(f"Failed: {failed_count}", file=sys.stderr)
    if orphaned:
        print(f"Orphaned: {len(orphaned)}", file=sys.stderr)
        if args.cleanup_orphaned:
            print(f"Deleted: {deleted_count}", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    
    # Output PRTG result
    status = "ok" if failed_count == 0 else "warning"
    message = f"Created {created_count}, existing {existing_count}, configured {configured_count}, failed {failed_count}"
    if args.cleanup_orphaned:
        message += f", deleted {deleted_count}"
    
    channels = [
        {
            "id": 10,
            "name": "Sensors Created",
            "type": "integer",
            "value": created_count,
            "kind": "count"
        },
        {
            "id": 11,
            "name": "Sensors Existing",
            "type": "integer",
            "value": existing_count,
            "kind": "count"
        },
        {
            "id": 12,
            "name": "Sensors Failed",
            "type": "integer",
            "value": failed_count,
            "kind": "count"
        },
        {
            "id": 13,
            "name": "Total Containers",
            "type": "integer",
            "value": len(containers),
            "kind": "count"
        },
        {
            "id": 14,
            "name": "Orphaned Sensors",
            "type": "integer",
            "value": len(orphaned),
            "kind": "count"
        },
        {
            "id": 15,
            "name": "Sensors Configured",
            "type": "integer",
            "value": configured_count,
            "kind": "count"
        }
    ]
    
    if args.cleanup_orphaned:
        channels.append({
            "id": 16,
            "name": "Sensors Deleted",
            "type": "integer",
            "value": deleted_count,
            "kind": "count"
        })
    
    print(json.dumps({
        "version": 2,
        "status": status,
        "message": message,
        "channels": channels
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        prtg_error("Interrupted by user")
    except Exception as e:
        import traceback
        print(traceback.format_exc(), file=sys.stderr)
        prtg_error(f"Unexpected error: {e}")