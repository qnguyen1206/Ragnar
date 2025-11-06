#!/usr/bin/env python3
"""
Test script to validate Bluetooth functionality in Ragnar
This script tests all the Bluetooth API endpoints to ensure they work correctly.
"""

import requests
import json
import time
import sys

def test_bluetooth_endpoints():
    """Test all Bluetooth API endpoints"""
    base_url = "http://localhost:8000"
    
    print("🔵 Testing Ragnar Bluetooth Functionality")
    print("=" * 50)
    
    # Test endpoints
    endpoints = [
        ("/api/bluetooth/status", "GET", None),
        ("/api/bluetooth/enable", "POST", None),
        ("/api/bluetooth/disable", "POST", None),
        ("/api/bluetooth/discoverable/on", "POST", None),
        ("/api/bluetooth/discoverable/off", "POST", None),
        ("/api/bluetooth/scan/start", "POST", None),
        ("/api/bluetooth/devices", "GET", None),
        ("/api/bluetooth/scan/stop", "POST", None),
        ("/api/bluetooth/enumerate", "POST", {"address": "00:00:00:00:00:00"}),
        ("/api/bluetooth/pair", "POST", {"address": "00:00:00:00:00:00"}),
        ("/api/bluetooth/unpair", "POST", {"address": "00:00:00:00:00:00"}),
    ]
    
    print("Testing Bluetooth API endpoints...")
    print("-" * 30)
    
    for endpoint, method, data in endpoints:
        try:
            print(f"Testing {method} {endpoint}...", end=" ")
            
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}", timeout=5)
            else:
                response = requests.post(f"{base_url}{endpoint}", 
                                       json=data, timeout=5)
            
            if response.status_code in [200, 201]:
                print("✅ OK")
                result = response.json()
                if endpoint == "/api/bluetooth/status":
                    print(f"   Status: {'Enabled' if result.get('enabled') else 'Disabled'}")
                elif endpoint == "/api/bluetooth/devices":
                    devices = result.get('devices', [])
                    print(f"   Found {len(devices)} devices")
                elif 'success' in result:
                    print(f"   {result.get('message', 'Success')}")
            else:
                print(f"❌ HTTP {response.status_code}")
                try:
                    error = response.json()
                    print(f"   Error: {error.get('error', 'Unknown error')}")
                except:
                    print(f"   Raw response: {response.text[:100]}")
                    
        except requests.exceptions.ConnectionError:
            print("❌ Connection failed (server not running?)")
        except requests.exceptions.Timeout:
            print("❌ Timeout")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    print("\n" + "=" * 50)
    print("🔵 Test completed!")
    
    print("\nTo start the Ragnar web interface:")
    print("python webapp_modern.py")
    print("\nThen visit: http://localhost:8000")
    print("Go to the 'Connect' tab to test Bluetooth functionality")

if __name__ == "__main__":
    test_bluetooth_endpoints()