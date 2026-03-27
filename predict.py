#!/usr/bin/env python3
"""
PhishGuard AI — CLI Prediction Tool

Usage:
    python predict.py <url>                   # Scan a single URL
    python predict.py --batch urls.txt        # Scan multiple URLs from file
    python predict.py --interactive           # Interactive mode
    python predict.py --train                 # Train/retrain the model
"""

import sys
import os
import argparse
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.feature_extractor import extract_features, features_to_vector, get_risk_flags
from src.utils import load_model, print_banner, format_result


def predict_url(url, model, scaler):
    """Predict if a URL is phishing or legitimate."""
    features = extract_features(url)
    vector = np.array([features_to_vector(features)])
    vector_scaled = scaler.transform(vector)
    
    prediction = model.predict(vector_scaled)[0]
    probability = model.predict_proba(vector_scaled)[0]
    confidence = probability[prediction] * 100
    flags = get_risk_flags(features)
    
    return {
        "prediction": prediction,
        "label": "PHISHING" if prediction == 1 else "SAFE",
        "confidence": confidence,
        "phishing_probability": probability[1] * 100,
        "flags": flags,
        "features": features,
    }


def scan_single(url, model, scaler):
    """Scan and display result for a single URL."""
    result = predict_url(url, model, scaler)
    print(format_result(url, result["prediction"], result["confidence"], result["flags"]))
    return result


def scan_batch(filepath, model, scaler):
    """Scan multiple URLs from a file."""
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        sys.exit(1)
    
    with open(filepath, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    
    print(f"\n📋 Scanning {len(urls)} URLs...\n")
    
    phishing_count = 0
    results = []
    
    for url in urls:
        result = predict_url(url, model, scaler)
        results.append(result)
        
        icon = "🚨" if result["prediction"] == 1 else "✅"
        conf = result["confidence"]
        
        if result["prediction"] == 1:
            phishing_count += 1
        
        display_url = url if len(url) <= 60 else url[:57] + "..."
        print(f"  {icon} [{conf:5.1f}%] {display_url}")
    
    print(f"\n{'=' * 50}")
    print(f"  📊 Summary: {phishing_count}/{len(urls)} flagged as phishing")
    print(f"{'=' * 50}")
    
    return results


def interactive_mode(model, scaler):
    """Interactive URL scanning mode."""
    print_banner()
    print("  Type a URL to scan, or 'quit' to exit.\n")
    
    while True:
        try:
            url = input("  🔍 URL > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  👋 Goodbye!")
            break
        
        if url.lower() in ("quit", "exit", "q"):
            print("\n  👋 Goodbye!")
            break
        
        if not url:
            continue
        
        scan_single(url, model, scaler)
        print()


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ PhishGuard AI — Phishing URL Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("--batch", metavar="FILE", help="Scan URLs from a text file")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--train", "-t", action="store_true", help="Train/retrain the model")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    
    args = parser.parse_args()
    
    # Train mode
    if args.train:
        from src.train import train
        train()
        return
    
    # Load model
    try:
        model, scaler, metadata = load_model()
    except FileNotFoundError:
        print("⚠️  No trained model found. Training now...\n")
        from src.train import train
        model, scaler = train()
        print()
    
    # Interactive mode
    if args.interactive:
        interactive_mode(model, scaler)
        return
    
    # Batch mode
    if args.batch:
        scan_batch(args.batch, model, scaler)
        return
    
    # Single URL mode
    if args.url:
        result = scan_single(args.url, model, scaler)
        
        if args.json:
            import json
            output = {
                "url": args.url,
                "prediction": result["label"],
                "confidence": round(result["confidence"], 2),
                "phishing_probability": round(result["phishing_probability"], 2),
                "flags": result["flags"],
            }
            print(json.dumps(output, indent=2))
        return
    
    # No args — show help
    parser.print_help()


if __name__ == "__main__":
    main()
