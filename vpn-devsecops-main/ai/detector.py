"""
detector.py — Real-time VPN Anomaly Detection
Detects: hping3 SYN flood, Scapy attacks, ike-scan reconnaissance
Checks every 3 seconds for faster detection.
"""

import os
import time
import traceback
import subprocess
import pandas as pd
import joblib
from datetime import datetime

# ── Step 1: Load model, scaler, encoders ─────────────────────────────────────
print("Step 1: Loading model, scaler and encoders...")
model    = joblib.load("model.pkl")
scaler   = joblib.load("scaler.pkl")
encoders = joblib.load("encoders.pkl")
print("All loaded successfully!")

# ── Step 2: Setup log file ────────────────────────────────────────────────────
print("\nStep 2: Setting up log file...")
os.makedirs("logs", exist_ok=True)
ALERT_LOG = "logs/alerts.log"
print(f"Alerts will be saved → {ALERT_LOG}")

print("\nStep 3: Starting real-time detection loop...")
print("="*60)
print("Monitoring VPN traffic... Press Ctrl+C to stop.")
print("="*60)

# ── Step 4: Real-time detection loop ─────────────────────────────────────────
while True:
    try:
        # Current time
        now          = datetime.now()
        current_hour = now.hour
        unusual_time = 1 if (current_hour >= 23 or current_hour <= 6) else 0

        # Default values matched to dataset ranges
        login_attempts      = 1      # dataset min=1
        failed_logins       = 0
        session_duration    = 792.0  # dataset mean
        network_packet_size = 500    # dataset mean
        ip_reputation_score = 0.33   # dataset mean
        total_packets       = 0

        # ── Read auth.log for SSH brute force ─────────────────────────────────
        if os.path.exists("/var/log/auth.log"):
            result = subprocess.run(
                ["tail", "-n", "10", "/var/log/auth.log"],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if "Accepted" in line or "session opened" in line:
                    login_attempts += 1
                if "Failed password" in line or "Invalid user" in line or "authentication failure" in line:
                    failed_logins  += 1
                    login_attempts += 1
        login_attempts = min(login_attempts, 13)
        failed_logins  = min(failed_logins, 5)

        # ── Run tcpdump for 3 seconds — detects hping3 + scapy ───────────────
        try:
            tcp_result = subprocess.run(
                ["sudo", "timeout", "3", "tcpdump", "-i", "tun0", "-c", "500", "-q"],
                capture_output=True, text=True
            )
            lines = tcp_result.stdout.splitlines()
            total_packets = len([l for l in lines if "IP" in l])

            # Map packet count to network_packet_size (dataset range 64-1285)
            if total_packets > 0:
                network_packet_size = min(max(64, total_packets * 13), 1285)

            # ── hping3 SYN flood detection ────────────────────────────────────
            if total_packets >= 50:
                failed_logins       = 5
                login_attempts      = 13
                ip_reputation_score = 0.01
                print(f"  [!] Flood detected: {total_packets} packets in 3s")

            # ── Scapy custom packet detection ─────────────────────────────────
            elif total_packets >= 20:
                failed_logins       = 3
                login_attempts      = 8
                ip_reputation_score = 0.1
                print(f"  [!] Suspicious traffic: {total_packets} packets in 3s")

        except Exception:
            pass

        # ── Check for ike-scan (port 500 UDP) ─────────────────────────────────
        try:
            ike_result = subprocess.run(
                ["sudo", "timeout", "2", "tcpdump", "-i", "ens33", "-c", "20",
                 "udp port 500", "-q"],
                capture_output=True, text=True
            )
            ike_lines = [l for l in ike_result.stdout.splitlines() if "IP" in l]
            if len(ike_lines) >= 3:
                ip_reputation_score = min(ip_reputation_score, 0.1)
                login_attempts      = max(login_attempts, 8)
                print(f"  [!] IKE scan detected: {len(ike_lines)} IKE packets")
        except Exception:
            pass

        # ── Check syslog ──────────────────────────────────────────────────────
        if os.path.exists("/var/log/syslog"):
            result = subprocess.run(
                ["tail", "-n", "10", "/var/log/syslog"],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if "error" in line.lower() or "refused" in line.lower():
                    ip_reputation_score = max(0.01, ip_reputation_score - 0.05)
                if "iptables" in line.lower() or "blocked" in line.lower():
                    ip_reputation_score = max(0.01, ip_reputation_score - 0.10)

        # ── Build feature row ─────────────────────────────────────────────────
        features = {
            "network_packet_size" : network_packet_size,
            "protocol_type"       : "TCP",
            "login_attempts"      : login_attempts,
            "session_duration"    : session_duration,
            "encryption_used"     : "AES",
            "ip_reputation_score" : ip_reputation_score,
            "failed_logins"       : failed_logins,
            "unusual_time_access" : unusual_time,
        }

        # ── Encode categoricals ───────────────────────────────────────────────
        df_live = pd.DataFrame([features])
        df_live["protocol_type"]   = encoders["protocol_type"].transform(["TCP"])[0]
        df_live["encryption_used"] = encoders["encryption_used"].transform(["AES"])[0]

        # ── Normalize ─────────────────────────────────────────────────────────
        df_scaled = pd.DataFrame(scaler.transform(df_live), columns=df_live.columns)

        # ── Predict ───────────────────────────────────────────────────────────
        prediction  = model.predict(df_scaled)[0]
        probability = model.predict_proba(df_scaled)[0][1]

        # ── Display result ────────────────────────────────────────────────────
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}]")
        print(f"  Total packets       : {total_packets} (in 3s)")
        print(f"  Failed logins       : {failed_logins}")
        print(f"  Login attempts      : {login_attempts}")
        print(f"  Packet size         : {network_packet_size}")
        print(f"  IP reputation score : {ip_reputation_score:.2f}")
        print(f"  Unusual time access : {unusual_time}")
        print(f"  Attack probability  : {probability*100:.1f}%")

        if prediction == 1:
            print("  Status : ATTACK DETECTED")
            with open(ALERT_LOG, "a") as f:
                f.write(f"[{timestamp}] ATTACK | prob={probability:.2f} | "
                        f"packets={total_packets} | "
                        f"failed_logins={failed_logins} | "
                        f"login_attempts={login_attempts} | "
                        f"packet_size={network_packet_size} | "
                        f"ip_score={ip_reputation_score:.2f}\n")
        else:
            print("  Status : NORMAL")

        print("  Next check in 3 seconds...")
        time.sleep(3)

    except KeyboardInterrupt:
        print("\nDetection stopped by user.")
        print(f"Alerts saved → {ALERT_LOG}")
        break

    except Exception as e:
        print(f"[ERROR] {e}")
        traceback.print_exc()
        time.sleep(3)