# Attack Logging API Documentation

## Overview

The Attack Logging API provides a centralized system for logging and retrieving attack outputs from Ragnar's offensive security actions. This system allows for better tracking, analysis, and debugging of attack operations.

## API Endpoint

**Base URL:** `http://localhost:8000/api/attack`

---

## POST `/api/attack` - Log Attack Output

Log a new attack output to the centralized system.

### Request Body (JSON)

```json
{
  "attack_type": "SSHBruteforce",
  "target_ip": "192.168.1.100",
  "target_port": "22",
  "status": "success",
  "message": "Successfully authenticated with credentials",
  "details": {
    "username": "admin",
    "password": "******",
    "attempts": 15,
    "duration_seconds": 45.2
  },
  "timestamp": "2025-11-12 14:30:45"
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `attack_type` | string | Yes | Type of attack (e.g., SSHBruteforce, FTPConnector, SQLBruteforce) |
| `target_ip` | string | Yes | IP address of the target |
| `target_port` | string | No | Port number of the attack |
| `status` | string | Yes | Attack status: `success`, `failed`, or `timeout` |
| `message` | string | No | Human-readable message describing the result |
| `details` | object | No | Additional attack details (credentials, files, etc.) |
| `timestamp` | string | No | Timestamp (auto-generated if not provided) |

### Response

**Success (201):**
```json
{
  "success": true,
  "message": "Attack output logged successfully",
  "log_entry": {
    "timestamp": "2025-11-12 14:30:45",
    "attack_type": "SSHBruteforce",
    "target_ip": "192.168.1.100",
    "target_port": "22",
    "status": "success",
    "message": "Successfully authenticated with credentials",
    "details": {
      "username": "admin",
      "attempts": 15
    }
  }
}
```

**Error (500):**
```json
{
  "success": false,
  "error": "Error message here"
}
```

---

## GET `/api/attack` - Retrieve Attack Logs

Retrieve attack logs with optional filtering.

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ip` | string | None | Filter by target IP address |
| `type` | string | None | Filter by attack type |
| `status` | string | None | Filter by status (success/failed/timeout) |
| `limit` | integer | 100 | Maximum number of logs to return |
| `days` | integer | 7 | Number of days to look back |

### Examples

**Get all attack logs:**
```
GET /api/attack
```

**Get logs for specific IP:**
```
GET /api/attack?ip=192.168.1.100
```

**Get only successful SSH attacks:**
```
GET /api/attack?type=SSHBruteforce&status=success
```

**Get last 50 failed attacks from past 3 days:**
```
GET /api/attack?status=failed&limit=50&days=3
```

### Response

```json
{
  "attack_logs": [
    {
      "timestamp": "2025-11-12 14:30:45",
      "attack_type": "SSHBruteforce",
      "target_ip": "192.168.1.100",
      "target_port": "22",
      "status": "success",
      "message": "Successfully authenticated",
      "details": {
        "username": "admin",
        "attempts": 15
      }
    },
    {
      "timestamp": "2025-11-12 14:25:30",
      "attack_type": "FTPConnector",
      "target_ip": "192.168.1.101",
      "target_port": "21",
      "status": "failed",
      "message": "All credential combinations failed",
      "details": {
        "attempts": 50
      }
    }
  ],
  "total_count": 250,
  "filtered_count": 2,
  "success_count": 1,
  "failed_count": 1,
  "filters_applied": {
    "ip": null,
    "type": null,
    "status": null,
    "days": 7,
    "limit": 100
  }
}
```

---

## Integration with Attack Actions

### Using the AttackLogger Utility

The `attack_logger.py` utility provides a simple Python interface for logging attacks.

**Import and Initialize:**
```python
from attack_logger import AttackLogger

class SSHBruteforce:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.attack_logger = AttackLogger()  # Initialize logger
```

**Log Successful Attack:**
```python
self.attack_logger.log_success(
    attack_type='SSHBruteforce',
    target_ip='192.168.1.100',
    target_port='22',
    message=f'Successfully authenticated as {username}',
    username=username,
    password='******',
    attempts=attempt_count,
    duration_seconds=45.2
)
```

**Log Failed Attack:**
```python
self.attack_logger.log_failure(
    attack_type='SSHBruteforce',
    target_ip='192.168.1.100',
    target_port='22',
    message='All credential combinations failed',
    attempts_made=total_attempts,
    credentials_tested=len(self.users) * len(self.passwords)
)
```

**Log Timeout:**
```python
self.attack_logger.log_timeout(
    attack_type='SSHBruteforce',
    target_ip='192.168.1.100',
    target_port='22',
    message='Connection timed out after 300 seconds',
    timeout_seconds=300
)
```

**Retrieve Logs for Target:**
```python
logs = self.attack_logger.get_attack_logs(
    ip='192.168.1.100',
    days=1
)

if logs:
    print(f"Total attacks on target: {logs['filtered_count']}")
    print(f"Successful: {logs['success_count']}")
    print(f"Failed: {logs['failed_count']}")
```

---

## Log Storage

Attack logs are stored as JSON files in the `data/logs/attacks/` directory:

```
data/logs/attacks/
├── attacks_2025-11-12.json
├── attacks_2025-11-11.json
└── attacks_2025-11-10.json
```

Each file contains an array of attack log entries for that day.

---

## Best Practices

1. **Always log attack outcomes** - Whether successful, failed, or timed out
2. **Include relevant details** - Usernames, file counts, error messages, etc.
3. **Use descriptive messages** - Make logs easy to understand
4. **Don't log sensitive data in plain text** - Mask passwords in logs
5. **Handle logging failures gracefully** - Don't let logging errors break attacks

---

## Example Attack Action Integration

Here's a complete example showing how to integrate attack logging into an existing attack action:

```python
"""
ssh_connector.py - Enhanced with attack logging
"""

from attack_logger import AttackLogger

class SSHBruteforce:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.ssh_connector = SSHConnector(shared_data)
        self.attack_logger = AttackLogger()
        logger.info("SSHConnector initialized with attack logging.")
    
    def execute(self, ip, port, row, status_key):
        """Execute the brute force attack with logging."""
        logger.info(f"Executing SSHBruteforce on {ip}:{port}...")
        self.shared_data.ragnarorch_status = "SSHBruteforce"
        
        try:
            success, results = self.bruteforce_ssh(ip, port)
            
            if success:
                # Log successful attack
                self.attack_logger.log_success(
                    attack_type='SSHBruteforce',
                    target_ip=ip,
                    target_port=port,
                    message=f'Successfully authenticated with {len(results)} credentials',
                    credentials_found=len(results),
                    usernames=[r['username'] for r in results]
                )
                return 'success'
            else:
                # Log failed attack
                self.attack_logger.log_failure(
                    attack_type='SSHBruteforce',
                    target_ip=ip,
                    target_port=port,
                    message='All credential combinations failed',
                    attempts_made=len(self.users) * len(self.passwords)
                )
                return 'failed'
                
        except Exception as e:
            # Log error/timeout
            self.attack_logger.log_failure(
                attack_type='SSHBruteforce',
                target_ip=ip,
                target_port=port,
                message=f'Attack error: {str(e)}',
                error=str(e)
            )
            return 'failed'
```

---

## Future Enhancements

Potential improvements to the attack logging system:

- Real-time attack log streaming via WebSocket
- Attack success rate analytics dashboard
- Export logs to CSV/JSON for analysis
- Integration with threat intelligence system
- Attack pattern detection and alerting
- Rate limiting and performance monitoring
