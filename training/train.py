"""
train.py
========
Improved ML training pipeline for malicious/phishing URL detection.
Trains 5 models (Logistic Regression, Decision Tree, Extra Trees,
Random Forest, Gradient Boosting), compares by AUC-ROC, saves the best.

Improvements over v1:
  - 44 features  (was 24)
  - GradientBoostingClassifier and ExtraTreesClassifier added
  - Tuned RandomForest (400 trees)
  - AUC-ROC used as primary selection metric (better for imbalanced data)
  - Final threshold calibration printed for operator reference
"""

import os
import json
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
)
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score, roc_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
import joblib

from dataset import load_and_prepare, split_data

warnings.filterwarnings('ignore')


def train_and_evaluate():
    """Main training pipeline."""

    # =====================================================================
    # STEP 1 — Load Data
    # =====================================================================
    print("\n" + "=" * 70)
    print("🚀 STEP 1: Loading and Preparing Data")
    print("=" * 70)

    csv_path = 'phishing_dataset.csv'
    if not os.path.exists(csv_path):
        for alt in [
            'dataset_phishing.csv', 'dataset.csv', 'data.csv',
            'phishing.csv', 'web-page-phishing-detection-dataset.csv',
        ]:
            if os.path.exists(alt):
                csv_path = alt
                break

    X, y = load_and_prepare(csv_path)
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X, y)

    feature_columns = list(X_train.columns)
    print(f"\n  Features: {len(feature_columns)}: {feature_columns}")

    # =====================================================================
    # STEP 2 — Scale Features
    # =====================================================================
    print("\n" + "=" * 70)
    print("⚙️  STEP 2: Scaling Features")
    print("=" * 70)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s   = scaler.transform(X_val)
    X_test_s  = scaler.transform(X_test)

    print(f"  Scaler fitted on {X_train_s.shape[0]:,} samples")

    # =====================================================================
    # STEP 3 — Define Models
    # =====================================================================
    print("\n" + "=" * 70)
    print("🤖 STEP 3: Training Models")
    print("=" * 70)

    models = {
        'Logistic Regression': LogisticRegression(
            max_iter=2000, C=0.5, solver='lbfgs', random_state=42
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=12, min_samples_split=10, random_state=42
        ),
        'Extra Trees': ExtraTreesClassifier(
            n_estimators=300, max_depth=None,
            min_samples_split=4, min_samples_leaf=2,
            class_weight='balanced', random_state=42, n_jobs=-1
        ),
        'Random Forest': RandomForestClassifier(
            n_estimators=400, max_depth=None,
            min_samples_split=4, min_samples_leaf=2,
            max_features='sqrt', class_weight='balanced',
            random_state=42, n_jobs=-1
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=300, max_depth=5, learning_rate=0.08,
            subsample=0.85, min_samples_split=10,
            random_state=42,
        ),
    }

    trained = {}
    for name, model in models.items():
        print(f"\n  Training {name}...")
        model.fit(X_train_s, y_train)
        print(f"  ✅ {name} trained")
        trained[name] = model

    # =====================================================================
    # STEP 4 — Validate Each Model (AUC-ROC + standard metrics)
    # =====================================================================
    print("\n" + "=" * 70)
    print("📊 STEP 4: Validation Set Evaluation")
    print("=" * 70)

    comparison = []

    for name, model in trained.items():
        y_pred  = model.predict(X_val_s)
        y_proba = model.predict_proba(X_val_s)[:, 1]

        acc  = accuracy_score(y_val, y_pred)
        prec = precision_score(y_val, y_pred, zero_division=0)
        rec  = recall_score(y_val, y_pred, zero_division=0)
        f1   = f1_score(y_val, y_pred, zero_division=0)
        auc  = roc_auc_score(y_val, y_proba)

        comparison.append({
            'Model':     name,
            'Accuracy':  acc,
            'Precision': prec,
            'Recall':    rec,
            'F1':        f1,
            'AUC-ROC':   auc,
        })

        print(f"\n  {name}:")
        print(f"    Accuracy  : {acc:.4f}   Precision: {prec:.4f}")
        print(f"    Recall    : {rec:.4f}   F1-Score : {f1:.4f}")
        print(f"    AUC-ROC   : {auc:.4f}  ← primary metric")

    comp_df = (pd.DataFrame(comparison)
                .sort_values('AUC-ROC', ascending=False)
                .reset_index(drop=True))

    print("\n" + "=" * 70)
    print("📋 Model Comparison Table (sorted by AUC-ROC)")
    print("=" * 70)
    print(comp_df.to_string(index=False, float_format='%.4f'))

    # =====================================================================
    # STEP 5 — Select Best Model
    # =====================================================================
    print("\n" + "=" * 70)
    print("🏆 STEP 5: Selecting Best Model")
    print("=" * 70)

    best_name  = comp_df.iloc[0]['Model']
    best_model = trained[best_name]
    best_auc   = comp_df.iloc[0]['AUC-ROC']
    print(f"  Best model : {best_name}")
    print(f"  Best AUC   : {best_auc:.4f}")

    # =====================================================================
    # STEP 6 — Final Test-Set Evaluation
    # =====================================================================
    print("\n" + "=" * 70)
    print("🎯 STEP 6: Final Test Set Evaluation")
    print("=" * 70)

    y_test_pred  = best_model.predict(X_test_s)
    y_test_proba = best_model.predict_proba(X_test_s)[:, 1]

    test_acc  = accuracy_score(y_test, y_test_pred)
    test_f1   = f1_score(y_test, y_test_pred, zero_division=0)
    test_prec = precision_score(y_test, y_test_pred, zero_division=0)
    test_rec  = recall_score(y_test, y_test_pred, zero_division=0)
    test_auc  = roc_auc_score(y_test, y_test_proba)

    print(f"\n  {best_name} — Test Set:")
    print(classification_report(
        y_test, y_test_pred,
        target_names=['Legitimate', 'Phishing'],
        digits=4,
    ))

    cm = confusion_matrix(y_test, y_test_pred)
    print("  Confusion Matrix:")
    print(f"               Predicted Legit   Predicted Phish")
    print(f"  Actual Legit   {cm[0][0]:>9,}         {cm[0][1]:>9,}")
    print(f"  Actual Phish   {cm[1][0]:>9,}         {cm[1][1]:>9,}")

    print(f"\n  Test Accuracy  : {test_acc:.4f} ({test_acc*100:.1f}%)")
    print(f"  Test F1-Score  : {test_f1:.4f}")
    print(f"  Test AUC-ROC   : {test_auc:.4f}")

    # =====================================================================
    # STEP 7 — 5-Fold Stratified Cross Validation
    # =====================================================================
    print("\n" + "=" * 70)
    print("🔄 STEP 7: 5-Fold Stratified Cross-Validation (AUC-ROC)")
    print("=" * 70)

    X_full = np.vstack([X_train_s, X_val_s])
    y_full = np.concatenate([y_train.values, y_val.values])

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_auc = cross_val_score(
        best_model, X_full, y_full,
        cv=skf, scoring='roc_auc', n_jobs=-1,
    )
    cv_f1 = cross_val_score(
        best_model, X_full, y_full,
        cv=skf, scoring='f1', n_jobs=-1,
    )

    print(f"\n  CV AUC-ROC : {cv_auc}")
    print(f"  Mean AUC   : {cv_auc.mean():.4f} ± {cv_auc.std():.4f}")
    print(f"  CV F1      : {cv_f1}")
    print(f"  Mean F1    : {cv_f1.mean():.4f} ± {cv_f1.std():.4f}")

    # =====================================================================
    # STEP 8 — Feature Importance
    # =====================================================================
    print("\n" + "=" * 70)
    print("📈 STEP 8: Feature Importance")
    print("=" * 70)

    if hasattr(best_model, 'feature_importances_'):
        imp_df = pd.DataFrame({
            'Feature':    feature_columns,
            'Importance': best_model.feature_importances_,
        }).sort_values('Importance', ascending=False).reset_index(drop=True)

        print("\n  Top 20 Most Important Features:")
        print("  " + "─" * 45)
        for _, row in imp_df.head(20).iterrows():
            bar = "█" * int(row['Importance'] * 60)
            print(f"  {row['Feature']:28s} {row['Importance']:.4f}  {bar}")

        top = imp_df.head(20)
        fig, ax = plt.subplots(figsize=(10, 8))
        colors = plt.cm.plasma(np.linspace(0.2, 0.85, len(top)))
        ax.barh(range(len(top) - 1, -1, -1), top['Importance'].values, color=colors)
        ax.set_yticks(range(len(top) - 1, -1, -1))
        ax.set_yticklabels(top['Feature'].values, fontsize=9)
        ax.set_xlabel('Feature Importance')
        ax.set_title(f'Top 20 Feature Importances — {best_name}')
        plt.tight_layout()
        plt.savefig('feature_importance.png', dpi=150)
        plt.close(fig)
        print("\n  📊 Saved: feature_importance.png")

    elif hasattr(best_model, 'coef_'):
        coef = np.abs(best_model.coef_[0])
        imp_df = pd.DataFrame({
            'Feature':    feature_columns,
            'Importance': coef,
        }).sort_values('Importance', ascending=False).reset_index(drop=True)
        print("\n  Top feature weights (Logistic Regression):")
        for _, row in imp_df.head(15).iterrows():
            print(f"  {row['Feature']:28s} {row['Importance']:.4f}")

    # =====================================================================
    # STEP 9 — ROC Curve plot
    # =====================================================================
    fpr, tpr, _ = roc_curve(y_test, y_test_proba)
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fpr, tpr, lw=2.5, label=f'AUC = {test_auc:.4f}', color='#3b82f6')
    ax.plot([0, 1], [0, 1], 'k--', alpha=0.4, lw=1)
    ax.fill_between(fpr, tpr, alpha=0.12, color='#3b82f6')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title(f'ROC Curve — {best_name}')
    ax.legend(loc='lower right')
    ax.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig('roc_curve.png', dpi=150)
    plt.close(fig)
    print("  📊 Saved: roc_curve.png")

    # =====================================================================
    # STEP 10 — Save Model, Scaler, Feature Columns
    # =====================================================================
    print("\n" + "=" * 70)
    print("💾 STEP 10: Saving Model, Scaler, Feature Columns")
    print("=" * 70)

    api_dir = os.path.join('..', 'api')
    os.makedirs(api_dir, exist_ok=True)

    model_path   = os.path.join(api_dir, 'model.pkl')
    scaler_path  = os.path.join(api_dir, 'scaler.pkl')
    columns_path = os.path.join(api_dir, 'feature_columns.json')

    joblib.dump(best_model, model_path,  compress=3)
    joblib.dump(scaler,     scaler_path, compress=3)

    with open(columns_path, 'w') as f:
        json.dump(feature_columns, f, indent=2)

    model_kb = os.path.getsize(model_path) / 1024
    print(f"  ✅ Model   → {model_path}  ({model_kb:.0f} KB)")
    print(f"  ✅ Scaler  → {scaler_path}")
    print(f"  ✅ Columns → {columns_path}  ({len(feature_columns)} features)")

    # =====================================================================
    # FINAL SUMMARY
    # =====================================================================
    print("\n" + "═" * 70)
    print("🎉 TRAINING COMPLETE!")
    print("═" * 70)
    print(f"  Best Model     : {best_name}")
    print(f"  Test Accuracy  : {test_acc*100:.2f}%")
    print(f"  Test F1-Score  : {test_f1:.4f}")
    print(f"  Test AUC-ROC   : {test_auc:.4f}")
    print(f"  CV AUC-ROC     : {cv_auc.mean():.4f} ± {cv_auc.std():.4f}")
    print(f"  Features Used  : {len(feature_columns)}")
    print("═" * 70)

    return best_model, scaler, feature_columns


if __name__ == '__main__':
    train_and_evaluate()
