import subprocess
import re
import os
from datetime import datetime
import config

def run_command(command):
    """
    Executes shell commands via bash to ensure compatibility between 
    Windows Git Bash and Linux environments.
    """
    # Forces execution through bash to avoid Windows CMD pathing issues
    result = subprocess.run(
        f'bash -c "{command}"', shell=True,
        capture_output=True, text=True
    )
    
    # Debug: Uncomment the line below if you need to see shell errors
    # if result.stderr: print(f"SHELL ERROR: {result.stderr.strip()}")
    
    return result.stdout

# ─── Collect failed logins ────────────────────────────────────────────────────
def get_failed_logins():
    """Counts 'Failed password' entries in the designated auth log."""
    output = run_command(rf"grep 'Failed password' '{config.AUTH_LOG}' | wc -l")
    try:
        return int(output.strip())
    except:
        return 0

# ─── Collect login attempts ───────────────────────────────────────────────────
def get_login_attempts():
    """Counts both successful and failed login attempts."""
    output = run_command(rf"grep -E 'Accepted|Failed' '{config.AUTH_LOG}' | wc -l")
    try:
        return int(output.strip())
    except:
        return 0

# ─── Collect packet size ──────────────────────────────────────────────────────
def get_packet_size():
    """
    Captures live traffic using tcpdump. 
    Note: This will return 0.0 on Windows as tcpdump requires a Linux interface.
    """
    output = run_command(
        "sudo tcpdump -i ens37 -c 10 -n 2>/dev/null | "
        "grep -oE 'length [0-9]+' | awk '{print $2}' | "
        "awk '{sum+=$1} END {if (NR>0) print sum/NR; else print 0}'"
    )
    try:
        return float(output.strip())
    except:
        return 0.0

# ─── Collect protocol type ────────────────────────────────────────────────────
def get_protocol():
    """Maps the most recent protocol found in the syslog to a numeric value."""
    output = run_command(rf"grep 'PROTO=' '{config.SYSLOG}' | tail -1")
    match = re.search(r'PROTO=([A-Z]+)', output)
    protocol = match.group(1) if match else ""
    mapping = {"TCP": 0, "UDP": 1, "ICMP": 2}
    return mapping.get(protocol, 0)

# ─── Collect session duration ─────────────────────────────────────────────────
def get_session_duration():
    """Calculates how long a VPN session has been active."""
    output = run_command(rf"grep 'Connected Since' '{config.OPENVPN_LOG}' 2>/dev/null")
    try:
        match = re.search(r'Connected Since,(.+)', output)
        if match:
            connected_since = match.group(1).strip()
            fmt = "%a %b %d %H:%M:%S %Y"
            start = datetime.strptime(connected_since, fmt)
            duration = (datetime.now() - start).total_seconds()
            return duration
        return 0.0
    except:
        return 0.0

# ─── Collect encryption used ──────────────────────────────────────────────────
def get_encryption():
    """Checks if AES-256 encryption is mentioned in the syslog."""
    output = run_command(rf"grep 'AES' '{config.SYSLOG}' | tail -1")
    return 1 if "AES-256" in output else 0

# ─── Collect unusual time access ─────────────────────────────────────────────
def get_unusual_time():
    """Flags access attempts occurring between midnight and 6 AM."""
    current_hour = datetime.now().hour
    return 1 if 0 <= current_hour <= 6 else 0

# ─── Collect IP reputation score ─────────────────────────────────────────────
def get_ip_reputation():
    """Calculates a score based on the frequency of the last failing IP."""
    # 1. Identify the last IP that failed to log in
    output = run_command(rf"grep 'Failed password' '{config.AUTH_LOG}' | tail -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'")
    ip = output.strip()
    
    if ip:
        # 2. Count total failures associated with that specific IP
        count_cmd = rf"grep 'Failed password' '{config.AUTH_LOG}' | grep '{ip}' | wc -l"
        count_output = run_command(count_cmd)
        try:
            attempts = int(count_output.strip())
            return min(attempts / 10, 1.0) 
        except:
            return 0.0
    return 0.0

# ─── Collect all features ────────────────────────────────────────────────────
def collect_features():
    """Aggregates all collected data into a dictionary for the model."""
    features = {
        "network_packet_size"  : get_packet_size(),
        "protocol_type"        : get_protocol(),
        "login_attempts"       : get_login_attempts(),
        "session_duration"     : get_session_duration(),
        "encryption_used"      : get_encryption(),
        "ip_reputation_score"  : get_ip_reputation(),
        "failed_logins"        : get_failed_logins(),
        "unusual_time_access"  : get_unusual_time(),
    }
    print(f"[{datetime.now()}] Features collected: {features}")
    return features

if __name__ == "__main__":
    collect_features()