"""
PhishGuard AI — Model Training
Trains a Random Forest classifier on URL features.
"""

import os
import sys
import csv
import json
import pickle
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    accuracy_score,
)
from sklearn.preprocessing import StandardScaler

from src.feature_extractor import extract_features, features_to_vector, get_feature_names


def load_dataset(path="data/dataset.csv"):
    """Load URL dataset from CSV."""
    urls, labels = [], []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))
    return urls, labels


def prepare_features(urls):
    """Extract features from a list of URLs."""
    feature_dicts = [extract_features(url) for url in urls]
    vectors = [features_to_vector(fd) for fd in feature_dicts]
    return np.array(vectors)


def train(dataset_path="data/dataset.csv", model_dir="models"):
    """Full training pipeline."""
    
    print("=" * 60)
    print("  🛡️  PhishGuard AI — Training Pipeline")
    print("=" * 60)
    
    # ── Step 1: Generate dataset if not exists ────────────
    if not os.path.exists(dataset_path):
        print("\n📦 Dataset not found. Generating...")
        from data.generate_dataset import generate_dataset
        generate_dataset(n_samples=5000, output_path=dataset_path)
    
    # ── Step 2: Load & extract features ───────────────────
    print("\n📥 Loading dataset...")
    urls, labels = load_dataset(dataset_path)
    print(f"   Loaded {len(urls)} URLs ({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate)")
    
    print("\n🔧 Extracting features...")
    X = prepare_features(urls)
    y = np.array(labels)
    feature_names = get_feature_names()
    print(f"   Extracted {X.shape[1]} features per URL")
    
    # ── Step 3: Split data ────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n📊 Train/Test split: {len(X_train)} train, {len(X_test)} test")
    
    # ── Step 4: Scale features ────────────────────────────
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # ── Step 5: Train model ───────────────────────────────
    print("\n🧠 Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train)
    
    # ── Step 6: Evaluate ──────────────────────────────────
    y_pred = model.predict(X_test_scaled)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    print(f"\n{'=' * 60}")
    print(f"  📊 Model Performance")
    print(f"{'=' * 60}")
    print(f"\n  Accuracy:  {accuracy:.4f}")
    print(f"  AUC-ROC:   {auc:.4f}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])}")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:")
    print(f"    {'':15s} Pred Legit  Pred Phish")
    print(f"    {'Actual Legit':15s}    {cm[0][0]:5d}       {cm[0][1]:5d}")
    print(f"    {'Actual Phish':15s}    {cm[1][0]:5d}       {cm[1][1]:5d}")
    
    # Cross-validation
    print("\n🔄 Cross-validation (5-fold)...")
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring="accuracy")
    print(f"   Mean CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    
    # Feature importance
    print(f"\n🏆 Top 10 Most Important Features:")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    for i in range(min(10, len(feature_names))):
        idx = indices[i]
        print(f"   {i+1:2d}. {feature_names[idx]:30s} {importances[idx]:.4f}")
    
    # ── Step 7: Save model & scaler ───────────────────────
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, "phishguard_model.pkl")
    scaler_path = os.path.join(model_dir, "scaler.pkl")
    meta_path = os.path.join(model_dir, "metadata.json")
    
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    
    metadata = {
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "accuracy": round(accuracy, 4),
        "auc_roc": round(auc, 4),
        "n_train_samples": len(X_train),
        "n_test_samples": len(X_test),
        "model_type": "RandomForestClassifier",
        "cv_mean_accuracy": round(cv_scores.mean(), 4),
    }
    
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\n💾 Model saved to: {model_path}")
    print(f"   Scaler saved to: {scaler_path}")
    print(f"   Metadata saved to: {meta_path}")
    print(f"\n{'=' * 60}")
    print(f"  ✅ Training complete!")
    print(f"{'=' * 60}")
    
    return model, scaler


if __name__ == "__main__":
    train()
