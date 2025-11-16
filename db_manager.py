# db_manager.py
# SQLite Database Manager for Ragnar - Replaces netkb.csv
#
# ARCHITECTURE:
# ============
# This module provides the single source of truth for all host/network data in Ragnar.
# It replaces the CSV-based netkb.csv with a robust SQLite database that supports:
# - Thread-safe concurrent read/write operations
# - Complex queries and filtering
# - Efficient indexing for fast lookups
# - Data integrity with foreign keys and constraints
# - Automatic migration from legacy CSV files
#
# DATA LIFECYCLE:
# ==============
# 1. Host Discovery: ARP scan, ping sweep, nmap → insert/update hosts
# 2. Port Scanning: Nmap port scans → update ports column
# 3. Vulnerability Scanning: Nmap vuln scanner → update vulnerabilities column
# 4. Attack Execution: Various actions → update action status columns
# 5. Ping Tracking: Continuous monitoring → update failed_ping_count, status
# 6. Cleanup: Remove hosts with last_seen > 24 hours ago
#
# STATUS STATES:
# =============
# - 'alive': Host responding to pings (failed_ping_count < 30)
# - 'degraded': Host failed 30 consecutive pings but seen within 24h
# - 'dead': Host not seen for 24+ hours (auto-deleted)
#
# MIGRATION:
# =========
# On first run, automatically migrates data from netkb.csv to SQLite.
# CSV file is kept for backward compatibility but becomes read-only.

import os
import sys
import sqlite3
import json
import csv
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from contextlib import contextmanager

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.abspath(__file__))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from logger import Logger

logger = Logger(name="db_manager.py", level=logging.INFO)

class DatabaseManager:
    """
    Thread-safe SQLite database manager for Ragnar host/network data.
    
    This class handles all database operations including:
    - Schema creation and migrations
    - CRUD operations for hosts
    - Ping failure tracking
    - Status management (alive/degraded/dead)
    - CSV migration and backward compatibility
    """
    
    def __init__(self, db_path: str = None, currentdir: str = None):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to SQLite database file (default: data/ragnar.db)
            currentdir: Root directory of Ragnar installation
        """
        self.currentdir = currentdir or os.path.dirname(os.path.abspath(__file__))
        self.datadir = os.path.join(self.currentdir, 'data')
        
        # Database file location
        if db_path is None:
            db_path = os.path.join(self.datadir, 'ragnar.db')
        
        self.db_path = db_path
        self.lock = threading.RLock()  # Reentrant lock for nested calls
        
        # Legacy CSV paths for migration
        self.netkb_csv = os.path.join(self.datadir, 'netkb.csv')
        
        # Initialize database
        self._init_database()
        
        logger.info(f"DatabaseManager initialized: {self.db_path}")
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures thread-safe access and automatic cleanup.
        
        Usage:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM hosts")
        """
        conn = None
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row  # Enable dict-like access
                conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign keys
                yield conn
                conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _init_database(self):
        """
        Initialize database schema and perform migrations.
        Creates tables if they don't exist and migrates CSV data if needed.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create hosts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    ports TEXT,
                    services TEXT,
                    vulnerabilities TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_ping_success TIMESTAMP,
                    failed_ping_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'alive',
                    alive_count INTEGER DEFAULT 0,
                    network_profile TEXT,
                    scanner_status TEXT,
                    ssh_connector TEXT,
                    rdp_connector TEXT,
                    ftp_connector TEXT,
                    smb_connector TEXT,
                    telnet_connector TEXT,
                    sql_connector TEXT,
                    steal_files_ssh TEXT,
                    steal_files_rdp TEXT,
                    steal_files_ftp TEXT,
                    steal_files_smb TEXT,
                    steal_files_telnet TEXT,
                    steal_data_sql TEXT,
                    nmap_vuln_scanner TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for fast lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac)
            """)
            
            # Create scan_history table for audit trail
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT,
                    ip TEXT,
                    scan_type TEXT,
                    ports_found TEXT,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (mac) REFERENCES hosts(mac) ON DELETE CASCADE
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_history_mac ON scan_history(mac)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp)
            """)
            
            conn.commit()
            logger.info("Database schema initialized successfully")
        
        # Perform CSV migration if needed
        self._migrate_from_csv()
        
        # Clean up any duplicate entries
        self.cleanup_duplicate_hosts()
    
    def _migrate_from_csv(self):
        """
        Migrate data from legacy netkb.csv to SQLite database.
        Only runs if CSV exists and database is empty.
        """
        if not os.path.exists(self.netkb_csv):
            logger.debug("No netkb.csv found - skipping migration")
            return
        
        # Check if database already has data
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM hosts")
            count = cursor.fetchone()[0]
            
            if count > 0:
                logger.debug(f"Database already contains {count} hosts - skipping CSV migration")
                return
        
        logger.info(f"Migrating data from {self.netkb_csv} to SQLite...")
        
        try:
            with open(self.netkb_csv, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                migrated_count = 0
                
                for row in reader:
                    try:
                        mac = row.get('MAC', '').strip()
                        if not mac or mac.upper() == 'UNKNOWN':
                            continue
                        
                        # Convert CSV row to database format
                        host_data = {
                            'mac': mac,
                            'ip': row.get('IP', '').strip(),
                            'hostname': row.get('Hostname', '').strip(),
                            'vendor': row.get('Vendor', '').strip(),
                            'ports': row.get('Ports', '').strip(),
                            'services': row.get('Services', '').strip() or row.get('Service', '').strip(),
                            'vulnerabilities': row.get('Nmap Vulnerabilities', '').strip(),
                            'alive_count': self._safe_int(row.get('Alive Count', 0)),
                            'network_profile': row.get('Network Profile', '').strip(),
                            'scanner_status': row.get('Scanner', '').strip(),
                            'ssh_connector': row.get('ssh_connector', '').strip(),
                            'rdp_connector': row.get('rdp_connector', '').strip(),
                            'ftp_connector': row.get('ftp_connector', '').strip(),
                            'smb_connector': row.get('smb_connector', '').strip(),
                            'telnet_connector': row.get('telnet_connector', '').strip(),
                            'sql_connector': row.get('sql_connector', '').strip(),
                            'steal_files_ssh': row.get('steal_files_ssh', '').strip(),
                            'steal_files_rdp': row.get('steal_files_rdp', '').strip(),
                            'steal_files_ftp': row.get('steal_files_ftp', '').strip(),
                            'steal_files_smb': row.get('steal_files_smb', '').strip(),
                            'steal_files_telnet': row.get('steal_files_telnet', '').strip(),
                            'steal_data_sql': row.get('steal_data_sql', '').strip(),
                            'nmap_vuln_scanner': row.get('nmap_vuln_scanner', '').strip(),
                            'notes': row.get('Notes', '').strip(),
                        }
                        
                        self.upsert_host(**host_data)
                        migrated_count += 1
                        
                    except Exception as e:
                        logger.warning(f"Failed to migrate row for MAC {mac}: {e}")
                        continue
                
                logger.info(f"✅ Successfully migrated {migrated_count} hosts from CSV to SQLite")
                
                # Backup CSV after successful migration
                backup_path = self.netkb_csv + '.migrated_backup'
                if not os.path.exists(backup_path):
                    import shutil
                    shutil.copy2(self.netkb_csv, backup_path)
                    logger.info(f"CSV backed up to: {backup_path}")
                    
        except Exception as e:
            logger.error(f"CSV migration failed: {e}")
    
    def _safe_int(self, value, default=0):
        """Safely convert value to integer."""
        try:
            return int(value) if value else default
        except (ValueError, TypeError):
            return default
    
    def _is_pseudo_mac(self, mac: str) -> bool:
        """Check if MAC is a pseudo-MAC (format: 00:00:c0:a8:xx:xx or similar)."""
        if not mac:
            return False
        return mac.lower().startswith('00:00:')
    
    def upsert_host(self, mac: str, ip: str = None, hostname: str = None, 
                   vendor: str = None, ports: str = None, services: str = None,
                   vulnerabilities: str = None, **kwargs):
        """
        Insert or update a host record.
        
        DUPLICATE PREVENTION:
        - If adding a real MAC for an IP that has a pseudo-MAC, migrates data and deletes pseudo-MAC
        - If adding a pseudo-MAC for an IP that has a real MAC, uses the real MAC instead
        - Prevents duplicate entries for the same IP with different MACs
        
        Args:
            mac: MAC address (primary key)
            ip: IP address
            hostname: Hostname
            vendor: Vendor/manufacturer
            ports: Comma-separated list of open ports
            services: JSON string or dict of port->service mappings
            vulnerabilities: JSON string or dict of vulnerabilities
            **kwargs: Additional columns (action statuses, notes, etc.)
        
        Returns:
            bool: True if successful
        """
        if not mac:
            logger.warning("Cannot upsert host without MAC address")
            return False
        
        # Normalize MAC address
        mac = mac.lower().strip()
        
        # DUPLICATE PREVENTION: Check for existing entry with same IP but different MAC
        if ip:
            existing_host = self.get_host_by_ip(ip)
            if existing_host and existing_host['mac'] != mac:
                existing_mac = existing_host['mac']
                is_new_mac_pseudo = self._is_pseudo_mac(mac)
                is_existing_mac_pseudo = self._is_pseudo_mac(existing_mac)
                
                if is_new_mac_pseudo and not is_existing_mac_pseudo:
                    # Trying to add pseudo-MAC when real MAC exists - use real MAC instead
                    logger.info(f"🔄 Real MAC {existing_mac} already exists for IP {ip}, ignoring pseudo-MAC {mac}")
                    mac = existing_mac
                elif not is_new_mac_pseudo and is_existing_mac_pseudo:
                    # Upgrading from pseudo-MAC to real MAC - migrate data
                    logger.info(f"🔄 Upgrading IP {ip} from pseudo-MAC {existing_mac} to real MAC {mac}")
                    
                    # Merge data from old entry with new data, preserving valuable info
                    # Ports: merge instead of replace to preserve scan history
                    existing_ports = set(existing_host.get('ports', '').split(',')) if existing_host.get('ports') else set()
                    new_ports = set(ports.split(',')) if ports else set()
                    merged_ports = ','.join(sorted(existing_ports.union(new_ports), key=lambda x: int(x) if x.isdigit() else 0))
                    
                    # Use new data if provided, otherwise keep existing
                    hostname = hostname or existing_host.get('hostname', '')
                    vendor = vendor or existing_host.get('vendor', '')
                    ports = merged_ports
                    services = services or existing_host.get('services', '')
                    vulnerabilities = vulnerabilities or existing_host.get('vulnerabilities', '')
                    
                    # Preserve action statuses and other metadata from pseudo-MAC entry
                    for field in ['alive_count', 'network_profile', 'scanner_status',
                                'ssh_connector', 'rdp_connector', 'ftp_connector',
                                'smb_connector', 'telnet_connector', 'sql_connector',
                                'steal_files_ssh', 'steal_files_rdp', 'steal_files_ftp',
                                'steal_files_smb', 'steal_files_telnet', 'steal_data_sql',
                                'nmap_vuln_scanner', 'notes', 'failed_ping_count']:
                        if field not in kwargs and existing_host.get(field):
                            kwargs[field] = existing_host[field]
                    
                    # Delete the old pseudo-MAC entry
                    self.delete_host(existing_mac)
                    logger.info(f"🗑️ Deleted old pseudo-MAC entry {existing_mac}")
                elif is_new_mac_pseudo and is_existing_mac_pseudo:
                    # Both are pseudo-MACs - keep the existing one
                    logger.debug(f"Both MACs are pseudo for IP {ip}, keeping existing {existing_mac}")
                    mac = existing_mac
                else:
                    # Both are real MACs but different - this is IP reassignment
                    logger.warning(f"⚠️ IP {ip} reassigned from MAC {existing_mac} to {mac} (both real MACs)")
                    # Continue with the new MAC, existing entry will be marked as failed ping
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if host exists
                cursor.execute("SELECT mac FROM hosts WHERE mac = ?", (mac,))
                exists = cursor.fetchone() is not None
                
                # Prepare data
                now = datetime.now().isoformat()
                
                if exists:
                    # Update existing host
                    update_fields = []
                    update_values = []
                    
                    if ip is not None:
                        update_fields.append("ip = ?")
                        update_values.append(ip)
                    
                    if hostname is not None:
                        update_fields.append("hostname = ?")
                        update_values.append(hostname)
                    
                    if vendor is not None:
                        update_fields.append("vendor = ?")
                        update_values.append(vendor)
                    
                    if ports is not None:
                        update_fields.append("ports = ?")
                        update_values.append(ports)
                    
                    if services is not None:
                        if isinstance(services, dict):
                            services = json.dumps(services)
                        update_fields.append("services = ?")
                        update_values.append(services)
                    
                    if vulnerabilities is not None:
                        if isinstance(vulnerabilities, dict):
                            vulnerabilities = json.dumps(vulnerabilities)
                        update_fields.append("vulnerabilities = ?")
                        update_values.append(vulnerabilities)
                    
                    # Handle additional kwargs
                    for key, value in kwargs.items():
                        if key in ['alive_count', 'network_profile', 'scanner_status',
                                  'ssh_connector', 'rdp_connector', 'ftp_connector',
                                  'smb_connector', 'telnet_connector', 'sql_connector',
                                  'steal_files_ssh', 'steal_files_rdp', 'steal_files_ftp',
                                  'steal_files_smb', 'steal_files_telnet', 'steal_data_sql',
                                  'nmap_vuln_scanner', 'notes', 'status', 'failed_ping_count']:
                            update_fields.append(f"{key} = ?")
                            update_values.append(value)
                    
                    # Always update last_seen and updated_at
                    update_fields.append("last_seen = ?")
                    update_values.append(now)
                    update_fields.append("updated_at = ?")
                    update_values.append(now)
                    
                    # Add MAC to end of values for WHERE clause
                    update_values.append(mac)
                    
                    if update_fields:
                        sql = f"UPDATE hosts SET {', '.join(update_fields)} WHERE mac = ?"
                        cursor.execute(sql, update_values)
                        logger.debug(f"Updated host: {mac} ({ip})")
                else:
                    # Insert new host
                    insert_data = {
                        'mac': mac,
                        'ip': ip or '',
                        'hostname': hostname or '',
                        'vendor': vendor or '',
                        'ports': ports or '',
                        'services': json.dumps(services) if isinstance(services, dict) else (services or ''),
                        'vulnerabilities': json.dumps(vulnerabilities) if isinstance(vulnerabilities, dict) else (vulnerabilities or ''),
                        'first_seen': now,
                        'last_seen': now,
                        'last_ping_success': now,
                        'failed_ping_count': 0,
                        'status': 'alive',
                        'alive_count': kwargs.get('alive_count', 0),
                        'network_profile': kwargs.get('network_profile', ''),
                        'scanner_status': kwargs.get('scanner_status', ''),
                        'ssh_connector': kwargs.get('ssh_connector', ''),
                        'rdp_connector': kwargs.get('rdp_connector', ''),
                        'ftp_connector': kwargs.get('ftp_connector', ''),
                        'smb_connector': kwargs.get('smb_connector', ''),
                        'telnet_connector': kwargs.get('telnet_connector', ''),
                        'sql_connector': kwargs.get('sql_connector', ''),
                        'steal_files_ssh': kwargs.get('steal_files_ssh', ''),
                        'steal_files_rdp': kwargs.get('steal_files_rdp', ''),
                        'steal_files_ftp': kwargs.get('steal_files_ftp', ''),
                        'steal_files_smb': kwargs.get('steal_files_smb', ''),
                        'steal_files_telnet': kwargs.get('steal_files_telnet', ''),
                        'steal_data_sql': kwargs.get('steal_data_sql', ''),
                        'nmap_vuln_scanner': kwargs.get('nmap_vuln_scanner', ''),
                        'notes': kwargs.get('notes', ''),
                    }
                    
                    columns = ', '.join(insert_data.keys())
                    placeholders = ', '.join(['?' for _ in insert_data])
                    sql = f"INSERT INTO hosts ({columns}) VALUES ({placeholders})"
                    
                    cursor.execute(sql, list(insert_data.values()))
                    logger.info(f"Inserted new host: {mac} ({ip})")
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to upsert host {mac}: {e}")
            return False
    
    def delete_host(self, mac: str) -> bool:
        """
        Delete a host record by MAC address.
        
        Args:
            mac: MAC address to delete
            
        Returns:
            bool: True if successful
        """
        if not mac:
            logger.warning("Cannot delete host without MAC address")
            return False
        
        # Normalize MAC address
        mac = mac.lower().strip()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM hosts WHERE mac = ?", (mac,))
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"Deleted host: {mac}")
                    return True
                else:
                    logger.debug(f"No host found to delete: {mac}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to delete host {mac}: {e}")
            return False
    
    def get_host_by_mac(self, mac: str) -> Optional[Dict]:
        """Get host record by MAC address."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM hosts WHERE mac = ?", (mac.lower().strip(),))
                row = cursor.fetchone()
                
                if row:
                    return dict(row)
                return None
        except Exception as e:
            logger.error(f"Failed to get host by MAC {mac}: {e}")
            return None
    
    def get_host_by_ip(self, ip: str) -> Optional[Dict]:
        """Get host record by IP address. If multiple exist, prefers real MAC over pseudo-MAC."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM hosts WHERE ip = ? ORDER BY mac", (ip.strip(),))
                rows = cursor.fetchall()
                
                if not rows:
                    return None
                
                # If multiple entries exist for same IP, prefer real MAC over pseudo-MAC
                if len(rows) > 1:
                    logger.warning(f"Found {len(rows)} entries for IP {ip} - preferring real MAC")
                    for row in rows:
                        if not self._is_pseudo_mac(row['mac']):
                            return dict(row)
                
                return dict(rows[0])
        except Exception as e:
            logger.error(f"Failed to get host by IP {ip}: {e}")
            return None
    
    def get_all_hosts(self, status: str = None) -> List[Dict]:
        """
        Get all hosts, optionally filtered by status.
        
        Args:
            status: Filter by status ('alive', 'degraded', None for all)
        
        Returns:
            List of host dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if status:
                    cursor.execute("SELECT * FROM hosts WHERE status = ? ORDER BY ip", (status,))
                else:
                    cursor.execute("SELECT * FROM hosts ORDER BY ip")
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get all hosts: {e}")
            return []
    
    def update_ping_status(self, mac: str, success: bool):
        """
        Update ping tracking for a host.
        
        Args:
            mac: MAC address
            success: True if ping succeeded, False if failed
        
        This implements the ping failure tracking logic:
        - Success: Reset failed_ping_count to 0, update last_ping_success, status='alive'
        - Failure: Increment failed_ping_count, check if >= 30 → status='degraded'
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                
                if success:
                    # Ping succeeded - reset failure count and mark alive
                    cursor.execute("""
                        UPDATE hosts 
                        SET failed_ping_count = 0,
                            last_ping_success = ?,
                            last_seen = ?,
                            status = 'alive',
                            updated_at = ?
                        WHERE mac = ?
                    """, (now, now, now, mac.lower().strip()))
                    logger.debug(f"Ping success: {mac} - status=alive")
                else:
                    # Ping failed - increment failure count
                    cursor.execute("""
                        UPDATE hosts 
                        SET failed_ping_count = failed_ping_count + 1,
                            updated_at = ?
                        WHERE mac = ?
                    """, (now, mac.lower().strip()))
                    
                    # Check if we've hit the degraded threshold (30 failed pings)
                    cursor.execute("SELECT failed_ping_count FROM hosts WHERE mac = ?", (mac.lower().strip(),))
                    row = cursor.fetchone()
                    
                    if row and row[0] >= 30:
                        cursor.execute("""
                            UPDATE hosts 
                            SET status = 'degraded'
                            WHERE mac = ?
                        """, (mac.lower().strip(),))
                        logger.warning(f"Host {mac} marked as degraded (30+ failed pings)")
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update ping status for {mac}: {e}")
            return False
    
    def cleanup_duplicate_hosts(self):
        """
        Remove duplicate host entries where the same IP exists with both:
        - A real MAC address (from ARP discovery)
        - A pseudo-MAC address (format 00:00:xx:xx:xx:xx)
        
        Priority: Real MAC addresses are kept, pseudo-MACs are deleted.
        Data from pseudo-MAC entries is migrated to real MAC entries.
        
        Returns:
            int: Number of duplicate entries removed
        """
        try:
            deleted_count = 0
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Find all IPs that have multiple MAC addresses
                cursor.execute("""
                    SELECT ip, COUNT(*) as count 
                    FROM hosts 
                    GROUP BY ip 
                    HAVING COUNT(*) > 1
                """)
                
                duplicate_ips = cursor.fetchall()
                
                if not duplicate_ips:
                    logger.debug("No duplicate IP entries found")
                    return 0
                
                logger.info(f"Found {len(duplicate_ips)} IPs with duplicate entries")
                
                for ip_row in duplicate_ips:
                    ip = ip_row['ip'] if isinstance(ip_row, sqlite3.Row) else ip_row[0]
                    
                    # Get all entries for this IP
                    cursor.execute("""
                        SELECT mac, hostname, vendor, ports, services, vulnerabilities,
                               last_seen, failed_ping_count, status, alive_count,
                               network_profile, scanner_status, ssh_connector, rdp_connector,
                               ftp_connector, smb_connector, telnet_connector, sql_connector,
                               steal_files_ssh, steal_files_rdp, steal_files_ftp,
                               steal_files_smb, steal_files_telnet, steal_data_sql,
                               nmap_vuln_scanner, notes
                        FROM hosts 
                        WHERE ip = ?
                        ORDER BY last_seen DESC
                    """, (ip,))
                    
                    entries = cursor.fetchall()
                    
                    if len(entries) < 2:
                        continue
                    
                    logger.debug(f"IP {ip} has {len(entries)} entries:")
                    
                    real_mac_entry = None
                    pseudo_mac_entries = []
                    
                    for entry in entries:
                        mac = entry['mac'] if isinstance(entry, sqlite3.Row) else entry[0]
                        logger.debug(f"  - MAC: {mac}, Status: {entry['status'] if isinstance(entry, sqlite3.Row) else entry[9]}")
                        
                        if self._is_pseudo_mac(mac):
                            pseudo_mac_entries.append(entry)
                        else:
                            if real_mac_entry is None:
                                real_mac_entry = entry
                            else:
                                # Multiple real MACs - keep the most recently seen
                                logger.warning(f"  Multiple real MACs for {ip}, keeping most recent")
                    
                    # Delete pseudo-MAC entries if we have a real MAC
                    if real_mac_entry and pseudo_mac_entries:
                        real_mac = real_mac_entry['mac'] if isinstance(real_mac_entry, sqlite3.Row) else real_mac_entry[0]
                        logger.info(f"  → Keeping real MAC: {real_mac}")
                        
                        # Merge ports from pseudo-MAC entries into real MAC
                        real_ports = set(real_mac_entry['ports'].split(',')) if real_mac_entry['ports'] else set()
                        for pseudo_entry in pseudo_mac_entries:
                            pseudo_mac = pseudo_entry['mac'] if isinstance(pseudo_entry, sqlite3.Row) else pseudo_entry[0]
                            pseudo_ports = set(pseudo_entry['ports'].split(',')) if pseudo_entry['ports'] else set()
                            real_ports.update(pseudo_ports)
                            
                            cursor.execute("DELETE FROM hosts WHERE mac = ?", (pseudo_mac,))
                            deleted_count += 1
                            logger.info(f"  → Deleted pseudo-MAC: {pseudo_mac}")
                        
                        # Update real MAC with merged ports
                        if real_ports:
                            merged_ports = ','.join(sorted([p for p in real_ports if p], key=lambda x: int(x) if x.isdigit() else 0))
                            cursor.execute("UPDATE hosts SET ports = ? WHERE mac = ?", (merged_ports, real_mac))
                    
                    elif len(pseudo_mac_entries) > 1:
                        # Multiple pseudo-MACs but no real MAC - keep newest, delete rest
                        keep_entry = pseudo_mac_entries[0]
                        keep_mac = keep_entry['mac'] if isinstance(keep_entry, sqlite3.Row) else keep_entry[0]
                        logger.info(f"  → No real MAC found, keeping newest pseudo-MAC: {keep_mac}")
                        
                        for pseudo_entry in pseudo_mac_entries[1:]:
                            pseudo_mac = pseudo_entry['mac'] if isinstance(pseudo_entry, sqlite3.Row) else pseudo_entry[0]
                            cursor.execute("DELETE FROM hosts WHERE mac = ?", (pseudo_mac,))
                            deleted_count += 1
                            logger.info(f"  → Deleted older pseudo-MAC: {pseudo_mac}")
                    
                    elif len(entries) > 1 and not real_mac_entry and not pseudo_mac_entries:
                        # Multiple real MACs - keep most recently seen
                        keep_entry = entries[0]
                        keep_mac = keep_entry['mac'] if isinstance(keep_entry, sqlite3.Row) else keep_entry[0]
                        logger.warning(f"  → Multiple real MACs, keeping most recent: {keep_mac}")
                        
                        for entry in entries[1:]:
                            old_mac = entry['mac'] if isinstance(entry, sqlite3.Row) else entry[0]
                            cursor.execute("DELETE FROM hosts WHERE mac = ?", (old_mac,))
                            deleted_count += 1
                            logger.info(f"  → Deleted older entry: {old_mac}")
                
                conn.commit()
                
                if deleted_count > 0:
                    logger.info(f"✅ Cleanup complete! Deleted {deleted_count} duplicate entries.")
                else:
                    logger.debug("No duplicates needed to be removed")
                
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error during duplicate cleanup: {e}")
            return 0
    
    def cleanup_old_hosts(self, hours: int = 24):
        """
        Remove hosts that haven't been seen in the specified number of hours.
        
        Args:
            hours: Number of hours after which to remove hosts (default: 24)
        
        Returns:
            int: Number of hosts removed
        """
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            cutoff_iso = cutoff_time.isoformat()
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get hosts to be removed for logging
                cursor.execute("""
                    SELECT mac, ip, hostname, last_seen 
                    FROM hosts 
                    WHERE last_seen < ?
                """, (cutoff_iso,))
                
                to_remove = cursor.fetchall()
                
                # Delete old hosts
                cursor.execute("DELETE FROM hosts WHERE last_seen < ?", (cutoff_iso,))
                
                removed_count = cursor.rowcount
                conn.commit()
                
                if removed_count > 0:
                    logger.info(f"Cleaned up {removed_count} hosts not seen in {hours} hours")
                    for row in to_remove:
                        logger.debug(f"  Removed: {row['mac']} ({row['ip']}) last seen {row['last_seen']}")
                
                return removed_count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old hosts: {e}")
            return 0
    
    def add_scan_history(self, mac: str, ip: str, scan_type: str, 
                        ports_found: str = None, vulnerabilities_found: int = 0):
        """
        Add a scan history entry for audit trail.
        
        Args:
            mac: MAC address
            ip: IP address
            scan_type: Type of scan (e.g., 'arp', 'nmap', 'vuln_scan')
            ports_found: Comma-separated list of ports found
            vulnerabilities_found: Number of vulnerabilities found
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scan_history (mac, ip, scan_type, ports_found, vulnerabilities_found)
                    VALUES (?, ?, ?, ?, ?)
                """, (mac.lower().strip(), ip, scan_type, ports_found or '', vulnerabilities_found))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to add scan history: {e}")
            return False
    
    def get_scan_history(self, mac: str = None, limit: int = 100) -> List[Dict]:
        """
        Get scan history, optionally filtered by MAC address.
        
        Args:
            mac: MAC address to filter by (None for all)
            limit: Maximum number of records to return
        
        Returns:
            List of scan history dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if mac:
                    cursor.execute("""
                        SELECT * FROM scan_history 
                        WHERE mac = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (mac.lower().strip(), limit))
                else:
                    cursor.execute("""
                        SELECT * FROM scan_history 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """
        Get database statistics.
        
        Returns:
            Dictionary with statistics like total hosts, alive hosts, etc.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Total hosts
                cursor.execute("SELECT COUNT(*) FROM hosts")
                stats['total_hosts'] = cursor.fetchone()[0]
                
                # Alive hosts
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'alive'")
                stats['alive_hosts'] = cursor.fetchone()[0]
                
                # Degraded hosts
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'degraded'")
                stats['degraded_hosts'] = cursor.fetchone()[0]
                
                # Hosts with open ports
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE ports != '' AND ports IS NOT NULL")
                stats['hosts_with_ports'] = cursor.fetchone()[0]
                
                # Hosts with vulnerabilities
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE vulnerabilities != '' AND vulnerabilities IS NOT NULL")
                stats['hosts_with_vulns'] = cursor.fetchone()[0]
                
                # Total scans
                cursor.execute("SELECT COUNT(*) FROM scan_history")
                stats['total_scans'] = cursor.fetchone()[0]
                
                return stats
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}
    
    def export_to_csv(self, csv_path: str = None) -> bool:
        """
        Export database to CSV format (for backward compatibility).
        
        Args:
            csv_path: Path to CSV file (default: netkb.csv)
        
        Returns:
            bool: True if successful
        """
        if csv_path is None:
            csv_path = self.netkb_csv
        
        try:
            hosts = self.get_all_hosts()
            
            if not hosts:
                logger.warning("No hosts to export")
                return False
            
            # Define CSV columns
            fieldnames = [
                'MAC', 'IP', 'Hostname', 'Vendor', 'Ports', 'Services',
                'Nmap Vulnerabilities', 'Alive Count', 'Network Profile',
                'Scanner', 'ssh_connector', 'rdp_connector', 'ftp_connector',
                'smb_connector', 'telnet_connector', 'sql_connector',
                'steal_files_ssh', 'steal_files_rdp', 'steal_files_ftp',
                'steal_files_smb', 'steal_files_telnet', 'steal_data_sql',
                'nmap_vuln_scanner', 'Notes', 'First Seen', 'Last Seen', 'Status'
            ]
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for host in hosts:
                    row = {
                        'MAC': host.get('mac', ''),
                        'IP': host.get('ip', ''),
                        'Hostname': host.get('hostname', ''),
                        'Vendor': host.get('vendor', ''),
                        'Ports': host.get('ports', ''),
                        'Services': host.get('services', ''),
                        'Nmap Vulnerabilities': host.get('vulnerabilities', ''),
                        'Alive Count': host.get('alive_count', 0),
                        'Network Profile': host.get('network_profile', ''),
                        'Scanner': host.get('scanner_status', ''),
                        'ssh_connector': host.get('ssh_connector', ''),
                        'rdp_connector': host.get('rdp_connector', ''),
                        'ftp_connector': host.get('ftp_connector', ''),
                        'smb_connector': host.get('smb_connector', ''),
                        'telnet_connector': host.get('telnet_connector', ''),
                        'sql_connector': host.get('sql_connector', ''),
                        'steal_files_ssh': host.get('steal_files_ssh', ''),
                        'steal_files_rdp': host.get('steal_files_rdp', ''),
                        'steal_files_ftp': host.get('steal_files_ftp', ''),
                        'steal_files_smb': host.get('steal_files_smb', ''),
                        'steal_files_telnet': host.get('steal_files_telnet', ''),
                        'steal_data_sql': host.get('steal_data_sql', ''),
                        'nmap_vuln_scanner': host.get('nmap_vuln_scanner', ''),
                        'Notes': host.get('notes', ''),
                        'First Seen': host.get('first_seen', ''),
                        'Last Seen': host.get('last_seen', ''),
                        'Status': host.get('status', ''),
                    }
                    writer.writerow(row)
            
            logger.info(f"Exported {len(hosts)} hosts to {csv_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export to CSV: {e}")
            return False


# Singleton instance
_db_instance = None
_db_lock = threading.Lock()

def get_db(currentdir: str = None) -> DatabaseManager:
    """
    Get singleton DatabaseManager instance.
    Thread-safe lazy initialization.
    
    Args:
        currentdir: Root directory of Ragnar installation
    
    Returns:
        DatabaseManager instance
    """
    global _db_instance
    
    if _db_instance is None:
        with _db_lock:
            if _db_instance is None:
                _db_instance = DatabaseManager(currentdir=currentdir)
    
    return _db_instance


if __name__ == "__main__":
    # Test the database manager
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    db = DatabaseManager()
    
    # Test upsert
    db.upsert_host(
        mac="aa:bb:cc:dd:ee:ff",
        ip="192.168.1.100",
        hostname="test-host",
        vendor="Test Vendor",
        ports="22,80,443"
    )
    
    # Test get
    host = db.get_host_by_mac("aa:bb:cc:dd:ee:ff")
    print(f"Host: {host}")
    
    # Test stats
    stats = db.get_stats()
    print(f"Stats: {stats}")
    
    # Test ping tracking
    db.update_ping_status("aa:bb:cc:dd:ee:ff", success=True)
    
    print("Database tests completed successfully!")
