"""
model.py — Train and Compare 3 Models for VPN Anomaly Detection
Models: Logistic Regression, SVM, Random Forest
Saves the best model based on F1 Score.
Simple version: no functions, runs top to bottom.
"""

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score,
    recall_score, f1_score, roc_auc_score
)

# ── Step 1: Load processed features and labels ────────────────────────────────
print("Step 1: Loading data...")
X = pd.read_csv("data/processed_features.csv")
y = pd.read_csv("data/labels.csv")["attack_detected"]
print(f"Features: {X.shape[0]} rows, {X.shape[1]} columns")
print(f"Label distribution → Normal: {sum(y==0)}, Attacks: {sum(y==1)}")

# ── Step 2: Train/Test split 80/20 stratified ─────────────────────────────────
print("\nStep 2: Splitting data (80% train, 20% test)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Training set : {X_train.shape[0]} samples")
print(f"Test set     : {X_test.shape[0]} samples")

# ── Step 3: Define the 3 models ───────────────────────────────────────────────
print("\nStep 3: Defining models...")

model_lr = LogisticRegression(
    max_iter=1000,       # enough iterations to converge
    random_state=42,
    n_jobs=-1
)

model_svm = SVC(
    kernel="rbf",
    C=1.0,
    gamma="scale",
    probability=True,    # needed for predict_proba (ROC AUC)
    random_state=42
)

model_rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    random_state=42,
    n_jobs=-1
)

models = {
    "Logistic Regression" : model_lr,
    "SVM"                 : model_svm,
    "Random Forest"       : model_rf
}

# ── Step 4: Train and evaluate all models ─────────────────────────────────────
print("\nStep 4: Training and evaluating all models...")
print("="*70)

results = {}

for name, model in models.items():
    print(f"\nTraining {name}...")
    model.fit(X_train, y_train)

    y_pred   = model.predict(X_test)
    y_scores = model.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_scores)

    results[name] = {
        "model"    : model,
        "accuracy" : acc,
        "precision": prec,
        "recall"   : rec,
        "f1"       : f1,
        "auc"      : auc
    }

    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1 Score  : {f1*100:.2f}%")
    print(f"  ROC AUC   : {auc:.4f}")

    # Overfitting check
    train_acc = accuracy_score(y_train, model.predict(X_train))
    if train_acc - acc > 0.10:
        print(f"  WARNING: Possible overfitting (train={train_acc*100:.1f}% vs test={acc*100:.1f}%)")
    else:
        print(f"  No overfitting detected (train={train_acc*100:.1f}% vs test={acc*100:.1f}%)")

# ── Step 5: Comparison table ──────────────────────────────────────────────────
print("\n")
print("="*70)
print("Step 5: Model Comparison")
print("="*70)
print(f"{'Model':<22} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'AUC':>10}")
print("-"*70)
for name, r in results.items():
    print(f"{name:<22} {r['accuracy']*100:>9.2f}% {r['precision']*100:>9.2f}% {r['recall']*100:>9.2f}% {r['f1']*100:>9.2f}% {r['auc']:>10.4f}")
print("="*70)

# ── Step 6: Select best model based on F1 Score ───────────────────────────────
print("\nStep 6: Selecting best model...")
best_name  = max(results, key=lambda x: results[x]["f1"])
best_model = results[best_name]["model"]
print(f"Best model : {best_name}")
print(f"Best F1    : {results[best_name]['f1']*100:.2f}%")
print(f"Best AUC   : {results[best_name]['auc']:.4f}")

# ── Step 7: Save best model and test set ──────────────────────────────────────
print("\nStep 7: Saving best model and test set...")
joblib.dump(best_model, "model.pkl")
joblib.dump(best_name,  "model_name.pkl")
X_test.to_csv("data/X_test.csv", index=False)
y_test.to_csv("data/y_test.csv", index=False)
print(f"Best model saved → model.pkl  ({best_name})")
print(f"Test set saved   → data/X_test.csv")

print("\nDone! Run evaluator.py to see full evaluation of the best model.")