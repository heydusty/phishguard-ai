"""
PhishGuard AI — Utility Functions
"""

import os
import pickle
import json


def load_model(model_dir="models"):
    """Load trained model, scaler, and metadata."""
    model_path = os.path.join(model_dir, "phishguard_model.pkl")
    scaler_path = os.path.join(model_dir, "scaler.pkl")
    meta_path = os.path.join(model_dir, "metadata.json")
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at {model_path}. Run 'python src/train.py' first."
        )
    
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    
    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)
    
    metadata = {}
    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            metadata = json.load(f)
    
    return model, scaler, metadata


def print_banner():
    """Print PhishGuard ASCII banner."""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║   🛡️  PhishGuard AI — URL Scanner         ║
    ║   Powered by Machine Learning             ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)


def format_result(url, prediction, confidence, flags):
    """Format prediction result for CLI output."""
    if prediction == 1:
        status = "🚨 PHISHING DETECTED"
        color_start = "\033[91m"  # Red
    else:
        status = "✅ SAFE"
        color_start = "\033[92m"  # Green
    
    color_end = "\033[0m"
    
    display_url = url if len(url) <= 50 else url[:47] + "..."
    
    output = f"""
╔{'═' * 56}╗
║  {color_start}{status} — Confidence: {confidence:.1f}%{color_end}{' ' * (56 - len(status) - 24)}║
║  URL: {display_url}{' ' * (50 - len(display_url))}║
╚{'═' * 56}╝"""
    
    if flags:
        output += "\n\nFeatures flagged:"
        for flag in flags:
            output += f"\n  {flag}"
    
    return output
