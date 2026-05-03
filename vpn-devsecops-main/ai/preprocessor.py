"""
preprocessor.py — Data Preprocessing for VPN Anomaly Detection
Supervised version: labels kept for Random Forest training.
Simple version: no functions, runs top to bottom.
"""

import os
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import joblib

# ── Step 1: Load the dataset ──────────────────────────────────────────────────
print("Step 1: Loading dataset...")
df = pd.read_csv("cybersecurity_intrusion_data.csv")
print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
print(df.head(3))

# ── Step 2: Drop unused columns ───────────────────────────────────────────────
print("\nStep 2: Dropping unused columns...")
df = df.drop(columns=["browser_type", "session_id"])
print(f"Columns after drop: {list(df.columns)}")

# ── Step 3: Handle missing values ─────────────────────────────────────────────
print("\nStep 3: Checking missing values...")
print(df.isnull().sum())
df = df.fillna(df.median(numeric_only=True))
df["protocol_type"]   = df["protocol_type"].fillna(df["protocol_type"].mode()[0])
df["encryption_used"] = df["encryption_used"].fillna(df["encryption_used"].mode()[0])
print("After filling:")
print(df.isnull().sum())
print("Missing values handled.")

# ── Step 4: Encode categorical columns ───────────────────────────────────────
print("\nStep 4: Encoding categorical columns...")
encoders = {}

le_protocol = LabelEncoder()
df["protocol_type"] = le_protocol.fit_transform(df["protocol_type"].astype(str))
encoders["protocol_type"] = le_protocol
print(f"protocol_type classes : {list(le_protocol.classes_)}")

le_encryption = LabelEncoder()
df["encryption_used"] = le_encryption.fit_transform(df["encryption_used"].astype(str))
encoders["encryption_used"] = le_encryption
print(f"encryption_used classes: {list(le_encryption.classes_)}")

joblib.dump(encoders, "encoders.pkl")
print("Encoders saved → encoders.pkl")

# ── Step 5: Select features + label ──────────────────────────────────────────
print("\nStep 5: Selecting features and label...")
features = [
    "network_packet_size",
    "protocol_type",
    "login_attempts",
    "session_duration",
    "encryption_used",
    "ip_reputation_score",
    "failed_logins",
    "unusual_time_access",
    "attack_detected",       # Label kept for supervised training
]
df = df[features]
print(f"Columns kept: {list(df.columns)}")

# ── Step 6: Separate features and label ──────────────────────────────────────
print("\nStep 6: Separating features and label...")
X = df.drop(columns=["attack_detected"])
y = df["attack_detected"]
print(f"Features shape : {X.shape}")
print(f"Label distribution → Normal: {sum(y==0)}, Attacks: {sum(y==1)}")

# ── Step 7: Normalize features ────────────────────────────────────────────────
print("\nStep 7: Normalizing features...")
scaler = MinMaxScaler()
X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
joblib.dump(scaler, "scaler.pkl")
print("Scaler saved → scaler.pkl")

# ── Step 8: Save processed data ───────────────────────────────────────────────
print("\nStep 8: Saving processed data...")
os.makedirs("data", exist_ok=True)
X_scaled.to_csv("data/processed_features.csv", index=False)
y.to_csv("data/labels.csv", index=False)
print("Saved → data/processed_features.csv")
print("Saved → data/labels.csv")

print("\nDone! Data is ready for Random Forest training.")
print(f"Features shape : {X_scaled.shape}")
print(f"Labels shape   : {y.shape}")