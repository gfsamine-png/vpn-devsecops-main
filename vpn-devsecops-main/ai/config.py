# ─── VMs Configuration ────────────────────────────────────────────────────────
SERVER_IP   = "192.168.138.10"
CLIENT_IP   = "192.168.138.20"

SERVER_USER = "zarboutt"
CLIENT_USER = "zarbout"

SSH_KEY_PATH = "/home/zarboutt/.ssh/ed25519"

import os

# Detect current folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_path(filename, system_path):
    # If the Linux system path exists, use it (VM mode)
    if os.path.exists(system_path):
        return system_path
    # Otherwise, use the local mock file (Windows mode)
    return os.path.join(BASE_DIR, filename)

# Paths will automatically adjust based on where the script is running
AUTH_LOG    = get_path("mock_auth.log", "/var/log/auth.log")
SYSLOG      = get_path("mock_auth.log", "/var/log/syslog")
OPENVPN_LOG = get_path("mock_auth.log", "/var/log/openvpn.log")
# ─── Model Configuration ──────────────────────────────────────────────────────
MODEL_PATH        = "/home/zarboutt/vpn-ai/model.pkl"
DATASET_PATH      = "/home/zarboutt/vpn-ai/cybersecurity_intrusion_data.csv"
COLLECTION_INTERVAL = 10  # seconds between each log collection

# ─── Isolation Forest Config ──────────────────────────────────────────────────
CONTAMINATION = 0.1   # 10% of data expected to be anomalous
RANDOM_STATE  = 42