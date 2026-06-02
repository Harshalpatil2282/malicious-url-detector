"""
evaluate.py
===========
Evaluation script for the trained phishing URL detection model.
Loads saved model, runs on test data, generates visualizations.
"""

import os
import json
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, confusion_matrix, classification_report
)
import joblib

from dataset import load_and_prepare, split_data

warnings.filterwarnings('ignore')


def evaluate_model():
    """Load saved model and evaluate on test data with visualizations."""
    
    api_dir = os.path.join('..', 'api')
    model_path = os.path.join(api_dir, 'model.pkl')
    scaler_path = os.path.join(api_dir, 'scaler.pkl')
    columns_path = os.path.join(api_dir, 'feature_columns.json')
    
    # =========================================================================
    # Load Model, Scaler, and Feature Columns
    # =========================================================================
    print("=" * 70)
    print("📂 Loading saved model and scaler...")
    print("=" * 70)
    
    if not os.path.exists(model_path):
        print(f"  ❌ Model not found at {model_path}")
        print("  Run train.py first!")
        return
    
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    with open(columns_path, 'r') as f:
        feature_columns = json.load(f)
    
    print(f"  Model : {type(model).__name__}")
    print(f"  Scaler: StandardScaler")
    print(f"  Features: {len(feature_columns)}")
    
    # =========================================================================
    # Load and Split Data
    # =========================================================================
    print("\n" + "=" * 70)
    print("📂 Loading test data...")
    print("=" * 70)
    
    csv_path = 'phishing_dataset.csv'
    if not os.path.exists(csv_path):
        for alt in ['dataset_phishing.csv', 'dataset.csv', 'data.csv', 'phishing.csv']:
            if os.path.exists(alt):
                csv_path = alt
                break
    
    X, y = load_and_prepare(csv_path)
    _, _, X_test, _, _, y_test = split_data(X, y)
    
    # Ensure columns match
    X_test = X_test[feature_columns] if all(c in X_test.columns for c in feature_columns) else X_test
    
    # Scale
    X_test_scaled = scaler.transform(X_test)
    
    # =========================================================================
    # Predictions
    # =========================================================================
    print("\n" + "=" * 70)
    print("🎯 Running Predictions on Test Set")
    print("=" * 70)
    
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]
    
    # =========================================================================
    # Metrics
    # =========================================================================
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_proba)
    
    print(f"\n  📊 Test Set Metrics:")
    print(f"  {'─' * 35}")
    print(f"  Accuracy  : {acc:.4f} ({acc*100:.1f}%)")
    print(f"  Precision : {prec:.4f} ({prec*100:.1f}%)")
    print(f"  Recall    : {rec:.4f} ({rec*100:.1f}%)")
    print(f"  F1-Score  : {f1:.4f} ({f1*100:.1f}%)")
    print(f"  AUC-ROC   : {auc:.4f} ({auc*100:.1f}%)")
    
    print(f"\n  Classification Report:")
    print("  " + "-" * 55)
    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])
    for line in report.split('\n'):
        print(f"  {line}")
    
    # =========================================================================
    # Confusion Matrix
    # =========================================================================
    print("\n" + "=" * 70)
    print("📊 Confusion Matrix")
    print("=" * 70)
    
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n                    Predicted Legit  Predicted Phish")
    print(f"  Actual Legit      {cm[0][0]:>14}  {cm[0][1]:>15}")
    print(f"  Actual Phish      {cm[1][0]:>14}  {cm[1][1]:>15}")
    
    # Plot confusion matrix heatmap
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm, annot=True, fmt='d', cmap='Blues',
        xticklabels=['Legitimate', 'Phishing'],
        yticklabels=['Legitimate', 'Phishing'],
        cbar_kws={'label': 'Count'}
    )
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.title('Confusion Matrix — Phishing URL Detection', fontsize=14)
    plt.tight_layout()
    plt.savefig('confusion_matrix.png', dpi=150)
    plt.close()
    print("\n  📊 Saved: confusion_matrix.png")
    
    # =========================================================================
    # ROC Curve
    # =========================================================================
    print("\n" + "=" * 70)
    print("📈 ROC Curve")
    print("=" * 70)
    
    fpr, tpr, thresholds = roc_curve(y_test, y_proba)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='#2196F3', lw=2.5, label=f'ROC Curve (AUC = {auc:.4f})')
    plt.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5, label='Random Classifier')
    plt.fill_between(fpr, tpr, alpha=0.15, color='#2196F3')
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('ROC Curve — Phishing URL Detection', fontsize=14)
    plt.legend(loc='lower right', fontsize=11)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig('roc_curve.png', dpi=150)
    plt.close()
    print(f"  AUC-ROC: {auc:.4f}")
    print("  📊 Saved: roc_curve.png")
    
    # =========================================================================
    # Error Analysis — False Positives & False Negatives
    # =========================================================================
    print("\n" + "=" * 70)
    print("🔍 Error Analysis")
    print("=" * 70)
    
    # False Positives: predicted phishing but actually legitimate
    fp_mask = (y_pred == 1) & (y_test.values == 0)
    fp_count = fp_mask.sum()
    
    # False Negatives: predicted legitimate but actually phishing
    fn_mask = (y_pred == 0) & (y_test.values == 1)
    fn_count = fn_mask.sum()
    
    print(f"\n  False Positives (legit flagged as phishing): {fp_count}")
    print(f"  False Negatives (phishing missed):           {fn_count}")
    print(f"  Total errors: {fp_count + fn_count} out of {len(y_test)}")
    print(f"  Error rate: {(fp_count + fn_count) / len(y_test) * 100:.2f}%")
    
    if fp_count > 0:
        print(f"\n  Sample False Positives (first 5):")
        fp_indices = np.where(fp_mask)[0][:5]
        for idx in fp_indices:
            prob = y_proba[idx]
            print(f"    Index {idx}: malicious_prob={prob:.4f}")
    
    if fn_count > 0:
        print(f"\n  Sample False Negatives (first 5):")
        fn_indices = np.where(fn_mask)[0][:5]
        for idx in fn_indices:
            prob = y_proba[idx]
            print(f"    Index {idx}: malicious_prob={prob:.4f}")
    
    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 70)
    print("🎉 EVALUATION COMPLETE!")
    print("=" * 70)
    print(f"  Model          : {type(model).__name__}")
    print(f"  Test Accuracy  : {acc*100:.1f}%")
    print(f"  Test F1-Score  : {f1*100:.1f}%")
    print(f"  AUC-ROC        : {auc*100:.1f}%")
    print(f"  False Positives: {fp_count}")
    print(f"  False Negatives: {fn_count}")
    print(f"  Saved Plots    : confusion_matrix.png, roc_curve.png")
    print("=" * 70)


if __name__ == '__main__':
    evaluate_model()
