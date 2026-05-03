"""
evaluator.py — Evaluate best model + compare all 3 on ROC curve
Models compared: Logistic Regression, SVM, Random Forest
Simple version: no functions, runs top to bottom.
"""

import os
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score,
    recall_score, f1_score,
    confusion_matrix, classification_report,
    roc_curve, roc_auc_score,
    precision_recall_curve, average_precision_score
)

# ── Step 1: Load data ─────────────────────────────────────────────────────────
print("Step 1: Loading data...")
X = pd.read_csv("data/processed_features.csv")
y = pd.read_csv("data/labels.csv")["attack_detected"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Test set: {X_test.shape[0]} samples")

# ── Step 2: Load best model ───────────────────────────────────────────────────
print("\nStep 2: Loading best model...")
best_model = joblib.load("model.pkl")
best_name  = joblib.load("model_name.pkl")
print(f"Best model: {best_name}")

# ── Step 3: Evaluate best model ───────────────────────────────────────────────
print("\nStep 3: Evaluating best model...")
y_pred   = best_model.predict(X_test)
y_scores = best_model.predict_proba(X_test)[:, 1]

accuracy  = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall    = recall_score(y_test, y_pred)
f1        = f1_score(y_test, y_pred)
auc       = roc_auc_score(y_test, y_scores)

print(f"\nBest Model ({best_name}) Results:")
print("="*50)
print(f"Accuracy  : {accuracy*100:.2f}%")
print(f"Precision : {precision*100:.2f}%")
print(f"Recall    : {recall*100:.2f}%")
print(f"F1 Score  : {f1*100:.2f}%")
print(f"ROC AUC   : {auc:.4f}")

# ── Step 4: Confusion Matrix ──────────────────────────────────────────────────
print("\nStep 4: Confusion Matrix")
print("="*50)
cm = confusion_matrix(y_test, y_pred)
print(f"                 Predicted Normal  Predicted Attack")
print(f"Real Normal    :       {cm[0][0]}              {cm[0][1]}")
print(f"Real Attack    :       {cm[1][0]}              {cm[1][1]}")
print(f"\nTrue  Negatives : {cm[0][0]}")
print(f"False Positives : {cm[0][1]}")
print(f"False Negatives : {cm[1][0]}")
print(f"True  Positives : {cm[1][1]}")

# ── Step 5: Classification report ────────────────────────────────────────────
print("\nStep 5: Full Classification Report")
print("="*50)
print(classification_report(y_test, y_pred,
      target_names=["Normal", "Attack"]))

# ── Step 6: ROC Curve for ALL 3 models ───────────────────────────────────────
print("Step 6: Generating ROC Curve comparison for all 3 models...")

all_models = {
    "Logistic Regression" : LogisticRegression(
        max_iter=1000, random_state=42, n_jobs=-1),
    "SVM"                 : SVC(
        kernel="rbf", C=1.0, gamma="scale",
        probability=True, random_state=42),
    "Random Forest"       : RandomForestClassifier(
        n_estimators=100, max_depth=None,
        random_state=42, n_jobs=-1)
}

colors = ["orange", "green", "blue"]

plt.figure(figsize=(9, 7))

for (name, model), color in zip(all_models.items(), colors):
    model.fit(X_train, y_train)
    scores      = model.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, scores)
    auc_val     = roc_auc_score(y_test, scores)
    marker      = " ★ BEST" if name == best_name else ""
    plt.plot(fpr, tpr, color=color, lw=2,
             label=f"{name}{marker} (AUC = {auc_val:.4f})")

plt.plot([0, 1], [0, 1], color="red", lw=1,
         linestyle="--", label="Random Classifier (AUC = 0.50)")
plt.xlabel("False Positive Rate (Normal flagged as Attack)")
plt.ylabel("True Positive Rate (Attack correctly detected)")
plt.title("ROC Curve — Logistic Regression vs SVM vs Random Forest")
plt.legend(loc="lower right")
plt.grid(True)
os.makedirs("logs", exist_ok=True)
plt.savefig("logs/roc_curve_comparison.png", dpi=150, bbox_inches="tight")
print("ROC Curve saved → logs/roc_curve_comparison.png")
plt.show()

# ── Step 7: Precision-Recall Curve for ALL 3 models ──────────────────────────
print("Step 7: Generating Precision-Recall Curve comparison for all 3 models...")

plt.figure(figsize=(9, 7))

for (name, model), color in zip(all_models.items(), colors):
    model.fit(X_train, y_train)
    scores = model.predict_proba(X_test)[:, 1]
    precision_vals, recall_vals, _ = precision_recall_curve(y_test, scores)
    ap_val = average_precision_score(y_test, scores)
    marker = " ★ BEST" if name == best_name else ""
    plt.plot(recall_vals, precision_vals, color=color, lw=2,
             label=f"{name}{marker} (AP = {ap_val:.4f})")

plt.xlabel("Recall (Attack detected)")
plt.ylabel("Precision (Detection accuracy)")
plt.title("Precision-Recall Curve Comparison — Logistic Regression vs SVM vs Random Forest")
plt.legend(loc="best")
plt.grid(True)
plt.savefig("logs/precision_recall_curve_comparison.png", dpi=150, bbox_inches="tight")
print("Precision-Recall Curve saved → logs/precision_recall_curve_comparison.png")
plt.show()

# ── Step 8: Save results ──────────────────────────────────────────────────────
print("\nStep 8: Saving results...")
results_df = pd.DataFrame({
    "real_label"         : y_test.values,
    "predicted_label"    : y_pred,
    "attack_probability" : y_scores
})
results_df.to_csv("logs/evaluation_results.csv", index=False)
print("Results saved → logs/evaluation_results.csv")

print(f"\nDone! Best model: {best_name} with AUC={auc:.4f}")