"""
dataset.py
==========
Data loading, cleaning, feature extraction, and splitting for phishing URL detection.
Handles both raw-URL datasets (applies feature extraction) and pre-computed feature datasets.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from feature_engineering import extract_url_features, get_feature_names


def load_and_prepare(csv_path: str):
    """
    Load and prepare the phishing dataset for training.

    Handles two dataset formats:
      1. Pre-computed features: CSV already has numeric feature columns + target
      2. Raw URLs: CSV has a 'url' column that needs feature extraction

    Parameters
    ----------
    csv_path : str
        Path to the CSV dataset file.

    Returns
    -------
    tuple[pd.DataFrame, pd.Series]
        (X, y) where X is features DataFrame, y is binary labels Series.
    """
    print("=" * 60)
    print("📂 Loading dataset...")
    print("=" * 60)

    df = pd.read_csv(csv_path)
    print(f"  Raw shape: {df.shape}")
    print(f"  Columns: {list(df.columns)}")

    # --- Drop missing values ---
    before = len(df)
    df.dropna(inplace=True)
    after = len(df)
    if before != after:
        print(f"  Dropped {before - after} rows with missing values")

    # --- Identify and encode target column ---
    target_col = None
    for col_name in ['status', 'label', 'target', 'phishing', 'Label', 'Status', 'Target', 'result', 'type', 'class']:
        if col_name in df.columns:
            target_col = col_name
            break

    if target_col is None:
        # Try the last column as target
        target_col = df.columns[-1]
        print(f"  ⚠ No standard target column found. Using last column: '{target_col}'")

    print(f"  Target column: '{target_col}'")
    print(f"  Unique target values: {df[target_col].unique()}")

    # Encode target to binary: 1 = phishing/malicious, 0 = legitimate/safe
    target_mapping = {}
    unique_vals = df[target_col].unique()

    if set(unique_vals).issubset({0, 1}):
        # Already binary
        y = df[target_col].astype(int)
        target_mapping = {0: 'legitimate', 1: 'phishing'}
    elif set(unique_vals).issubset({-1, 1}):
        # -1/1 encoding
        y = df[target_col].map({-1: 0, 1: 1}).astype(int)
        target_mapping = {-1: 'legitimate', 1: 'phishing'}
    else:
        # String labels
        label_map = {}
        for val in unique_vals:
            val_lower = str(val).lower().strip()
            if val_lower in ('phishing', 'malicious', 'bad', 'spam', 'suspicious', '1', 'yes'):
                label_map[val] = 1
            elif val_lower in ('legitimate', 'safe', 'good', 'benign', 'ham', '0', 'no'):
                label_map[val] = 0
            else:
                # Attempt numeric conversion
                try:
                    label_map[val] = int(float(val))
                except (ValueError, TypeError):
                    print(f"  ⚠ Unknown label '{val}' — mapping to 0 (legitimate)")
                    label_map[val] = 0
        y = df[target_col].map(label_map).astype(int)
        target_mapping = label_map

    print(f"  Target mapping: {target_mapping}")

    # --- Feature Extraction ---
    # CRITICAL: When a URL column exists, ALWAYS extract features from it
    # to ensure consistency between training and API inference.
    # The API only has the raw URL at inference time, so the model must
    # be trained on the same URL-derived features.

    url_col = None
    for col_name in ['url', 'URL', 'Url', 'uri', 'URI']:
        if col_name in df.columns:
            url_col = col_name
            break

    if url_col is not None:
        # Extract features from raw URLs (ensures API feature consistency)
        print(f"\n  🔧 Extracting URL-based features from '{url_col}' column...")
        print(f"     (Using our feature extractor for training-inference consistency)")
        feature_dicts = []
        urls = df[url_col].tolist()
        total = len(urls)
        for i, url in enumerate(urls):
            if i % 2000 == 0:
                print(f"    Progress: {i}/{total} URLs ({i/total*100:.1f}%)...")
            feature_dicts.append(extract_url_features(str(url)))
        X = pd.DataFrame(feature_dicts)
        print(f"  ✅ Extracted {X.shape[1]} features from {X.shape[0]} URLs")
    else:
        # No URL column — use existing numeric features
        columns_to_drop = [target_col]
        remaining_cols = [c for c in df.columns if c not in columns_to_drop]
        numeric_cols = df[remaining_cols].select_dtypes(include=[np.number]).columns.tolist()

        if len(numeric_cols) >= 5:
            print(f"\n  ✅ Using {len(numeric_cols)} pre-computed numeric features")
            X = df[numeric_cols].copy()
            X.fillna(0, inplace=True)
        else:
            print(f"\n  ⚠ Using all remaining columns as features")
            X = df.drop(columns=columns_to_drop, errors='ignore')
            for col in X.columns:
                X[col] = pd.to_numeric(X[col], errors='coerce')
            X.fillna(0, inplace=True)

    # --- Summary ---
    print(f"\n{'=' * 60}")
    print(f"📊 Dataset Summary")
    print(f"{'=' * 60}")
    print(f"  Feature matrix shape : {X.shape}")
    print(f"  Number of features   : {X.shape[1]}")
    print(f"  Feature names        : {list(X.columns)}")
    print(f"\n  Class distribution:")
    class_counts = y.value_counts()
    for label_val, count in class_counts.items():
        pct = count / len(y) * 100
        label_name = 'Phishing' if label_val == 1 else 'Legitimate'
        print(f"    {label_name} ({label_val}): {count:,} ({pct:.1f}%)")
    print(f"  Total samples        : {len(y):,}")

    return X, y


def split_data(X, y, test_size=0.2, val_size=0.1):
    """
    Stratified split into train/validation/test sets.

    Parameters
    ----------
    X : pd.DataFrame
        Feature matrix.
    y : pd.Series
        Target labels.
    test_size : float
        Fraction for test set (default 0.2).
    val_size : float
        Fraction for validation set (default 0.1).

    Returns
    -------
    tuple
        (X_train, X_val, X_test, y_train, y_val, y_test)
    """
    # First split: separate test set
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )

    # Second split: separate validation set from remaining
    # Adjust val_size relative to remaining data
    relative_val_size = val_size / (1 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=relative_val_size, stratify=y_temp, random_state=42
    )

    print(f"\n{'=' * 60}")
    print(f"📦 Data Split Summary")
    print(f"{'=' * 60}")
    print(f"  Training set   : {X_train.shape[0]:,} samples ({X_train.shape[0]/len(y)*100:.1f}%)")
    print(f"  Validation set : {X_val.shape[0]:,} samples ({X_val.shape[0]/len(y)*100:.1f}%)")
    print(f"  Test set       : {X_test.shape[0]:,} samples ({X_test.shape[0]/len(y)*100:.1f}%)")
    print(f"  Total          : {len(y):,} samples")

    return X_train, X_val, X_test, y_train, y_val, y_test


if __name__ == '__main__':
    import sys
    csv_path = sys.argv[1] if len(sys.argv) > 1 else 'phishing_dataset.csv'
    X, y = load_and_prepare(csv_path)
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X, y)
    print("\n✅ Dataset loaded and split successfully!")
