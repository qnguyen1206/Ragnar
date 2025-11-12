#!/usr/bin/env python3
"""
test_attack_logging.py - Test script for the attack logging API

This script demonstrates how to use the attack logging endpoint
and verifies that it's working correctly.
"""

import json
import time
from attack_logger import AttackLogger


def test_attack_logging():
    """Test the attack logging functionality."""
    print("=" * 70)
    print("ATTACK LOGGING API TEST")
    print("=" * 70)
    print()
    
    # Initialize attack logger
    print("1. Initializing AttackLogger...")
    attack_logger = AttackLogger(api_base_url="http://localhost:8000")
    print("   ✓ AttackLogger initialized")
    print()
    
    # Test 1: Log a successful SSH attack
    print("2. Testing successful attack logging...")
    success = attack_logger.log_success(
        attack_type='SSHBruteforce',
        target_ip='192.168.1.100',
        target_port='22',
        message='Successfully authenticated as admin',
        username='admin',
        password='******',
        attempts=15,
        duration_seconds=45.2
    )
    
    if success:
        print("   ✓ Successful attack logged")
    else:
        print("   ✗ Failed to log successful attack")
    print()
    
    # Test 2: Log a failed FTP attack
    print("3. Testing failed attack logging...")
    success = attack_logger.log_failure(
        attack_type='FTPConnector',
        target_ip='192.168.1.101',
        target_port='21',
        message='All credential combinations failed',
        attempts_made=50,
        credentials_tested=250
    )
    
    if success:
        print("   ✓ Failed attack logged")
    else:
        print("   ✗ Failed to log failed attack")
    print()
    
    # Test 3: Log a timeout
    print("4. Testing timeout logging...")
    success = attack_logger.log_timeout(
        attack_type='RDPConnector',
        target_ip='192.168.1.102',
        target_port='3389',
        message='Connection timed out after 300 seconds',
        timeout_seconds=300
    )
    
    if success:
        print("   ✓ Timeout logged")
    else:
        print("   ✗ Failed to log timeout")
    print()
    
    # Test 4: Log multiple attacks for different IPs
    print("5. Testing bulk logging...")
    test_attacks = [
        {
            'type': 'SMBBruteforce',
            'ip': '192.168.1.103',
            'port': '445',
            'status': 'success',
            'msg': 'Accessed share \\\\target\\admin'
        },
        {
            'type': 'SQLBruteforce',
            'ip': '192.168.1.104',
            'port': '1433',
            'status': 'failed',
            'msg': 'Connection refused'
        },
        {
            'type': 'TelnetBruteforce',
            'ip': '192.168.1.105',
            'port': '23',
            'status': 'success',
            'msg': 'Logged in with default credentials'
        }
    ]
    
    for i, attack in enumerate(test_attacks, 1):
        if attack['status'] == 'success':
            result = attack_logger.log_success(
                attack_type=attack['type'],
                target_ip=attack['ip'],
                target_port=attack['port'],
                message=attack['msg']
            )
        else:
            result = attack_logger.log_failure(
                attack_type=attack['type'],
                target_ip=attack['ip'],
                target_port=attack['port'],
                message=attack['msg']
            )
        
        print(f"   Attack {i}/3: {'✓' if result else '✗'}")
    
    print()
    
    # Wait a moment to ensure logs are written
    time.sleep(1)
    
    # Test 5: Retrieve all logs
    print("6. Testing log retrieval (all logs)...")
    logs = attack_logger.get_attack_logs(limit=100, days=1)
    
    if logs:
        print(f"   ✓ Retrieved logs successfully")
        print(f"   Total logs: {logs['total_count']}")
        print(f"   Filtered logs: {logs['filtered_count']}")
        print(f"   Success count: {logs['success_count']}")
        print(f"   Failed count: {logs['failed_count']}")
    else:
        print("   ✗ Failed to retrieve logs")
    print()
    
    # Test 6: Retrieve logs for specific IP
    print("7. Testing filtered log retrieval (IP: 192.168.1.100)...")
    logs = attack_logger.get_attack_logs(ip='192.168.1.100', days=1)
    
    if logs:
        print(f"   ✓ Retrieved filtered logs")
        print(f"   Filtered logs: {logs['filtered_count']}")
        if logs['attack_logs']:
            print(f"   Sample log:")
            sample = logs['attack_logs'][0]
            print(f"     - Type: {sample['attack_type']}")
            print(f"     - IP: {sample['target_ip']}")
            print(f"     - Status: {sample['status']}")
            print(f"     - Message: {sample['message']}")
    else:
        print("   ✗ Failed to retrieve filtered logs")
    print()
    
    # Test 7: Retrieve only successful attacks
    print("8. Testing status filtering (success only)...")
    logs = attack_logger.get_attack_logs(status='success', days=1)
    
    if logs:
        print(f"   ✓ Retrieved success logs")
        print(f"   Success count: {logs['success_count']}")
        print(f"   Attack types:")
        attack_types = set(log['attack_type'] for log in logs['attack_logs'])
        for attack_type in attack_types:
            print(f"     - {attack_type}")
    else:
        print("   ✗ Failed to retrieve success logs")
    print()
    
    print("=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)
    print()
    print("Summary:")
    print("--------")
    print("The attack logging API is working correctly if all tests passed.")
    print()
    print("Next steps:")
    print("1. Check the data/logs/attacks/ directory for JSON log files")
    print("2. Access http://localhost:8000/api/attack in your browser to view logs")
    print("3. Integrate AttackLogger into your attack action files")
    print()


def demo_attack_types():
    """Demonstrate logging different attack types."""
    print("=" * 70)
    print("ATTACK TYPE DEMONSTRATIONS")
    print("=" * 70)
    print()
    
    attack_logger = AttackLogger()
    
    # SSH Bruteforce
    print("Demo 1: SSH Bruteforce Attack")
    attack_logger.log_success(
        attack_type='SSHBruteforce',
        target_ip='10.0.0.50',
        target_port='22',
        message='Compromised SSH server with weak credentials',
        username='root',
        authentication_method='password',
        shell_access=True
    )
    print("   ✓ Logged")
    print()
    
    # FTP File Stealing
    print("Demo 2: FTP Data Exfiltration")
    attack_logger.log_success(
        attack_type='StealFilesFTP',
        target_ip='10.0.0.51',
        target_port='21',
        message='Exfiltrated 15 files from FTP server',
        files_stolen=15,
        total_size_mb=124.5,
        file_types=['pdf', 'doc', 'xls']
    )
    print("   ✓ Logged")
    print()
    
    # SQL Injection
    print("Demo 3: SQL Database Compromise")
    attack_logger.log_success(
        attack_type='SQLBruteforce',
        target_ip='10.0.0.52',
        target_port='1433',
        message='Gained sa privileges on MSSQL server',
        database_version='Microsoft SQL Server 2019',
        databases_found=['master', 'msdb', 'users', 'products']
    )
    print("   ✓ Logged")
    print()
    
    # Vulnerability Scan
    print("Demo 4: Vulnerability Discovery")
    attack_logger.log_success(
        attack_type='NmapVulnScanner',
        target_ip='10.0.0.53',
        target_port='443',
        message='Found 3 critical vulnerabilities',
        vulnerabilities=['CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9012'],
        severity='critical'
    )
    print("   ✓ Logged")
    print()
    
    print("=" * 70)
    print("All demos logged successfully!")
    print("=" * 70)


if __name__ == '__main__':
    import sys
    
    print()
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║            RAGNAR ATTACK LOGGING API TEST SUITE                   ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print()
    print("IMPORTANT: Make sure the Flask web server is running on port 8000")
    print("           before running these tests!")
    print()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        demo_attack_types()
    else:
        test_attack_logging()
        print()
        print("To see attack type demonstrations, run:")
        print("  python test_attack_logging.py demo")
        print()
