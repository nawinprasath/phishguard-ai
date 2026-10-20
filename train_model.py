"""
PhishGuard - Model Training Script (train_model.py)
===================================================
Loads a local labeled CSV dataset, extracts lexical features, trains 3 models
(Logistic Regression, Random Forest, Gradient Boosting), evaluates them with
stratified train-test split, and serializes the best model + metrics.json.
"""

import os
import sys
import json
import time
from datetime import datetime

import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from feature_extractor import extract_features, FEATURE_NAMES

# ==============================================================================
# 1. USER CONFIGURATION (Change path as needed)
# ==============================================================================
# Path to your local Kaggle "Phishing Site URLs" CSV (or similar dataset)
DATASET_PATH = "phishing_site_urls.csv"

# Set to an integer (e.g. 30000) for fast training in development, or None to use 100% of data
SAMPLE_LIMIT = 40000

# Fixed seed for strictly reproducible results
RANDOM_STATE = 42

MODEL_OUTPUT_PATH = "model.joblib"
METRICS_OUTPUT_PATH = "metrics.json"


def load_and_clean_data(filepath: str) -> pd.DataFrame:
    """
    Loads dataset, standardizes columns to lowercase, drops duplicates & missing values,
    and maps labels to 0 (Legitimate/Good) and 1 (Phishing/Bad).
    """
    if not os.path.exists(filepath):
        print("\n" + "=" * 70)
        print("ERROR: Dataset file not found!")
        print(f"Looked for: '{os.path.abspath(filepath)}'")
        print("=" * 70)
        print("How to fix this:")
        print("1. Download the 'Phishing Site URLs' dataset from Kaggle:")
        print("   https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls")
        print("2. Extract the file 'phishing_site_urls.csv' into this project folder.")
        print("3. Alternatively, update the DATASET_PATH variable at the top of train_model.py.")
        print("=" * 70 + "\n")
        sys.exit(1)

    print(f"[*] Reading dataset from: {filepath}")
    # Read with low_memory=False to handle large CSV smoothly
    df = pd.read_csv(filepath, low_memory=False)

    # Standardize column headers: strip whitespace & lowercase
    df.columns = [c.strip().lower() for c in df.columns]

    # Map possible column naming variations
    url_col = next((c for c in ['url', 'urls', 'url_address'] if c in df.columns), None)
    label_col = next((c for c in ['label', 'labels', 'class', 'result', 'target'] if c in df.columns), None)

    if not url_col or not label_col:
        print(f"[-] Could not find URL or Label column. Available columns: {list(df.columns)}")
        sys.exit(1)

    raw_count = len(df)
    print(f"[*] Raw dataset loaded: {raw_count:,} rows")

    # Drop missing values
    df = df.dropna(subset=[url_col, label_col])

    # Drop duplicate URLs
    df = df.drop_duplicates(subset=[url_col]).reset_index(drop=True)
    dedup_count = len(df)
    print(f"[*] After dropping nulls and duplicates: {dedup_count:,} unique URLs (removed {raw_count - dedup_count:,} duplicates)")

    # Map labels to binary: 0 = Legitimate (good), 1 = Phishing (bad)
    label_map = {
        'good': 0, 'legitimate': 0, 'safe': 0, 'benign': 0, '0': 0, 0: 0,
        'bad': 1, 'phishing': 1, 'malicious': 1, '1': 1, 1: 1
    }

    df['target'] = df[label_col].astype(str).str.strip().str.lower().map(label_map)

    # Filter out any unmapped labels
    df = df.dropna(subset=['target'])
    df['target'] = df['target'].astype(int)
    df['clean_url'] = df[url_col].astype(str)

    legit_count = (df['target'] == 0).sum()
    phish_count = (df['target'] == 1).sum()
    print(f"[*] Class Distribution: {legit_count:,} Legitimate (0) | {phish_count:,} Phishing (1)")

    # Optional balanced sampling for rapid training
    if SAMPLE_LIMIT and len(df) > SAMPLE_LIMIT:
        print(f"[*] Sampling a balanced subset of {SAMPLE_LIMIT:,} URLs (set SAMPLE_LIMIT = None for full data)...")
        per_class = SAMPLE_LIMIT // 2
        df_phish = df[df['target'] == 1].sample(min(per_class, phish_count), random_state=RANDOM_STATE)
        df_legit = df[df['target'] == 0].sample(min(per_class, legit_count), random_state=RANDOM_STATE)
        df = pd.concat([df_phish, df_legit]).sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
        print(f"[*] Active working dataset size: {len(df):,} URLs")

    return df[['clean_url', 'target']]


def extract_all_features(df: pd.DataFrame) -> (pd.DataFrame, np.ndarray):
    """
    Extracts lexical features for all URLs in the dataframe.
    """
    print(f"[*] Extracting {len(FEATURE_NAMES)} lexical features from {len(df):,} URLs...")
    start_time = time.time()

    records = [extract_features(u) for u in df['clean_url']]
    X = pd.DataFrame(records)[FEATURE_NAMES]
    y = df['target'].values

    elapsed = time.time() - start_time
    print(f"[+] Feature extraction completed in {elapsed:.2f} seconds.")
    return X, y


def train_and_evaluate_models(X: pd.DataFrame, y: np.ndarray):
    """
    Splits data 80/20 stratified, fits 3 models, prints evaluation metrics,
    and returns comparison results and the best model package.
    """
    print(f"\n[*] Performing 80/20 Stratified Train-Test Split (random_state={RANDOM_STATE})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )
    print(f"    Train size: {X_train.shape[0]:,} samples")
    print(f"    Test size : {X_test.shape[0]:,} samples")

    # Fit scaler for algorithms that benefit from standardized input (Logistic Regression)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Define model candidates
    candidate_models = {
        "Logistic Regression": {
            "estimator": LogisticRegression(max_iter=1000, random_state=RANDOM_STATE),
            "use_scaled": True
        },
        "Random Forest": {
            "estimator": RandomForestClassifier(n_estimators=100, max_depth=16, random_state=RANDOM_STATE, n_jobs=-1),
            "use_scaled": False
        },
        "Gradient Boosting": {
            "estimator": GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=RANDOM_STATE),
            "use_scaled": False
        }
    }

    eval_results = []
    trained_artifacts = {}

    print("\n" + "=" * 78)
    print(f"{'MODEL TRAINING AND EVALUATION':^78}")
    print("=" * 78)

    for name, config in candidate_models.items():
        print(f"\n--- Training: {name} ---")
        clf = config["estimator"]
        X_tr = X_train_scaled if config["use_scaled"] else X_train
        X_te = X_test_scaled if config["use_scaled"] else X_test

        t0 = time.time()
        clf.fit(X_tr, y_train)
        fit_time = time.time() - t0

        # Predict on holdout test set
        y_pred = clf.predict(X_te)

        # Compute metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        print(f"  Training Time : {fit_time:.2f}s")
        print(f"  Accuracy      : {acc:.4%}")
        print(f"  Precision     : {prec:.4%}")
        print(f"  Recall        : {rec:.4%}")
        print(f"  F1-Score      : {f1:.4%}")
        print(f"  Confusion Matrix:")
        print(f"    [[TN={tn:5d}, FP={fp:5d}]")
        print(f"     [FN={fn:5d}, TP={tp:5d}]]")

        eval_results.append({
            "model_name": name,
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": {
                "tn": int(tn), "fp": int(fp),
                "fn": int(fn), "tp": int(tp)
            },
            "training_time_sec": round(fit_time, 2)
        })

        trained_artifacts[name] = {
            "model": clf,
            "use_scaled": config["use_scaled"]
        }

    # Select best model by F1-Score (balances precision and recall for security)
    eval_results.sort(key=lambda x: x["f1_score"], reverse=True)
    best_summary = eval_results[0]
    best_name = best_summary["model_name"]
    best_clf = trained_artifacts[best_name]["model"]
    needs_scale = trained_artifacts[best_name]["use_scaled"]

    print("\n" + "=" * 78)
    print(f"[*] BEST MODEL SELECTED: {best_name}")
    print(f"   Accuracy: {best_summary['accuracy']:.2%} | F1-Score: {best_summary['f1_score']:.2%}")
    print("=" * 78)

    # Package model for inference
    best_package = {
        "model": best_clf,
        "model_name": best_name,
        "scaler": scaler,
        "requires_scaling": needs_scale,
        "feature_names": FEATURE_NAMES
    }

    # Build metrics.json metadata
    metrics_payload = {
        "dataset_name": os.path.basename(DATASET_PATH),
        "total_dataset_size": int(len(X)),
        "train_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "num_features": len(FEATURE_NAMES),
        "best_model": best_name,
        "accuracy": best_summary["accuracy"],
        "precision": best_summary["precision"],
        "recall": best_summary["recall"],
        "f1_score": best_summary["f1_score"],
        "confusion_matrix": best_summary["confusion_matrix"],
        "all_models": eval_results,
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    return best_package, metrics_payload


def main():
    print("\n" + "#" * 78)
    print(" " * 20 + "PHISHGUARD - MODEL TRAINING PIPELINE")
    print("#" * 78 + "\n")

    # 1. Load and clean
    df = load_and_clean_data(DATASET_PATH)

    # 2. Extract features
    X, y = extract_all_features(df)

    # 3. Train, compare, and select best
    best_package, metrics = train_and_evaluate_models(X, y)

    # 4. Save model with joblib
    joblib.dump(best_package, MODEL_OUTPUT_PATH)
    print(f"\n[+] Saved best model artifact to: '{MODEL_OUTPUT_PATH}'")

    # 5. Save metrics.json
    with open(METRICS_OUTPUT_PATH, "w") as f:
        json.dump(metrics, f, indent=4)
    print(f"[+] Saved model performance metrics to: '{METRICS_OUTPUT_PATH}'")

    print("\n[OK] Training pipeline complete! You can now launch the web app with: python app.py\n")


if __name__ == "__main__":
    main()
