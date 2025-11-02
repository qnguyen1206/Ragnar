# WiFi-Specific Network Scan Results Implementation

## Overview
This implementation creates a persistent network scan results system that:
1. Saves scan results to WiFi-specific CSV files 
2. Automatically loads the correct file based on current WiFi connection
3. Maintains persistent data across reboots
4. Updates data incrementally without clearing previous results

## Key Features

### 1. WiFi-Specific Data Storage
- Network scan results are saved to files named `network_{wifi_ssid}.csv` 
- Files are stored in `data/network_data/` directory
- Each WiFi network gets its own persistent data file
- SSID names are sanitized for safe filename usage

### 2. Persistent Data Format
The CSV files contain these columns:
- **IP**: Host IP address
- **Hostname**: Discovered hostname 
- **Alive**: 1 for online, 0 for offline
- **MAC**: MAC address if discovered
- **Ports**: Semicolon-separated list of open ports
- **LastSeen**: ISO timestamp of last detection

### 3. Automatic Updates
- `update_wifi_network_data()` merges new scan results with existing data
- Called automatically when Network Scan Results tab is accessed
- Also called during `sync_all_counts()` to keep data current
- Preserves historical data while adding new discoveries

### 4. Smart Data Merging
- Existing IP entries are updated with new information
- Ports are merged (existing + new ports)
- Hostnames and MACs are updated if better data is found
- Last seen timestamps are refreshed

## Functions Added

### `get_current_wifi_ssid()`
- Gets current WiFi SSID from wifi_manager or nmcli command
- Sanitizes SSID for safe filename usage
- Falls back to "unknown_network" if detection fails

### `get_wifi_specific_network_file()`
- Returns the file path for current WiFi network data
- Creates directory structure if needed
- Format: `data/network_data/network_{ssid}.csv`

### `update_wifi_network_data()`
- Reads all `result_*.csv` files from scan results directory
- Merges with existing WiFi-specific data
- Writes updated data back to WiFi-specific file
- Preserves historical information

### `read_wifi_network_data()`
- Reads network data from current WiFi-specific file
- Returns standardized format for web interface
- Returns empty list if no file exists

## API Endpoint Changes

### `/api/network`
- Now calls `update_wifi_network_data()` first
- Reads from WiFi-specific persistent file
- Falls back to legacy behavior if no persistent data
- Logs which WiFi network is being served

### `/network_data` (Legacy HTML endpoint)
- Updated to use WiFi-specific persistent data
- Shows current WiFi network name in header
- Displays "Persistent data" message
- Better error messages with WiFi context

## Benefits

### 1. Persistence
- Data survives reboots and service restarts
- No more losing scan results when page refreshes
- Historical view of network over time

### 2. WiFi-Specific Intelligence
- Different data for different networks
- Automatically switches when WiFi changes
- Useful for penetration testing multiple networks

### 3. Incremental Updates
- New scans add to existing data
- Previous discoveries are preserved
- Ports accumulate over multiple scans

### 4. Better User Experience
- Consistent data display
- Clear indication of which network
- Faster loading (no need to rebuild from scratch)

## File Structure
```
data/
├── network_data/
│   ├── network_HomeWiFi.csv
│   ├── network_OfficeNetwork.csv
│   └── network_unknown_network.csv
└── output/
    └── scan_results/
        ├── result_20231102_143022.csv
        └── result_20231102_143155.csv
```

## Testing
Test data has been created in:
- `data/output/scan_results/result_test.csv`

This simulates scan results for testing the system.

## Backwards Compatibility
- Falls back to legacy behavior if no WiFi-specific data
- Existing endpoints continue to work
- No breaking changes to API contracts