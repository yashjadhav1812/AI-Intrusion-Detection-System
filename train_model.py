import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.utils import resample

FEATURES = [
    "protocol", "flow_duration", "total_forward_packets",
    "total_backward_packets", "total_forward_packets_length",
    "total_backward_packets_length", "forward_packet_length_mean",
    "backward_packet_length_mean", "forward_packets_per_second",
    "backward_packets_per_second", "forward_iat_mean",
    "backward_iat_mean", "flow_iat_mean",
    "flow_packets_per_seconds", "flow_bytes_per_seconds"
]

from sklearn.calibration import CalibratedClassifierCV

model = CalibratedClassifierCV(model, method='sigmoid')
model.fit(X_train, y_train)

# Load CSV
csv_path = "Dataset/DrDoS_DNS.csv"
if not os.path.exists(csv_path):
    csv_path = "/Users/yash/Downloads/DrDoS_DNS.csv"

print(f"Loading: {csv_path}")
df = pd.read_csv(csv_path)
df.columns = df.columns.str.strip()
print(f"Shape: {df.shape}")
print("Label distribution:")
print(df["label"].value_counts())

X = df[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
y = df["label"]

# ── Balancing: use real attack rows + real+synthetic BENIGN ──
print("\nBalancing dataset...")
target_n = 10000

# Attack: downsample to target_n
df_attack = X[y == "DrDoS_DNS"].copy()
df_attack["__label__"] = "DrDoS_DNS"
df_attack = resample(df_attack, replace=False, n_samples=target_n, random_state=42)

# BENIGN real rows
df_benign_real_X = X[y == "BENIGN"].copy()
n_benign_real = len(df_benign_real_X)
benign_mean = df_benign_real_X.mean()
benign_std  = df_benign_real_X.std().fillna(1).clip(lower=0.01)

# Generate synthetic BENIGN from real stats
np.random.seed(42)
print("\nBalancing dataset...")

# Separate classes
df_attack = df[df["label"] != "BENIGN"]
df_benign = df[df["label"] == "BENIGN"]

# Downsample attack to match benign
df_attack = resample(df_attack,
                     replace=False,
                     n_samples=len(df_benign),
                     random_state=42)

df_balanced = pd.concat([df_attack, df_benign])
df_balanced = df_balanced.sample(frac=1, random_state=42)

X_bal = df_balanced[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
y_bal = df_balanced["label"]


# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X_bal, y_bal, test_size=0.2, random_state=42, stratify=y_bal)
print(f"Training on {len(X_train)} samples...")

# Train
model = RandomForestClassifier(
    n_estimators=150, max_depth=10
min_samples_split=10
min_samples_leaf=5
    class_weight="balanced", random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(f"\nModel Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(classification_report(y_test, y_pred))

# Sanity check with actual values from your app buttons
print("\nSanity check:")
benign_test = pd.DataFrame([[6,45000,8,6,1200,900,150,150,18,13,55000,70000,60000,31,4600]], columns=FEATURES)
print(f"  Normal button values  → {model.predict(benign_test)[0]}")

attack_test = pd.DataFrame([[17,40,1,600,62,360000,62,600,3500,45000,8,5,6,75000,2800000]], columns=FEATURES)
print(f"  Attack button values  → {model.predict(attack_test)[0]}")

# Save
os.makedirs("model", exist_ok=True)
with open("model/ids_model.pkl", "wb") as f:
    pickle.dump(model, f)
print("\nModel saved! Run python3 app.py to start.")
