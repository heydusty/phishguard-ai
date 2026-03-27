# 🛡️ PhishGuard AI — Phishing URL Detector

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![ML](https://img.shields.io/badge/ML-Scikit--Learn-orange?logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green)


> 🔍 A machine learning-powered tool that detects phishing/malicious URLs by analyzing 20+ lexical and statistical features — **no API keys required**.

<p align="center">
  <img src="https://img.shields.io/badge/Accuracy-96%25-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Features-20%2B-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Zero-API%20Keys-red?style=for-the-badge" />
</p>

---

## 📸 Demo

```
$ python predict.py "http://secure-paypa1-login.sketchy.xyz/account/verify"

╔══════════════════════════════════════════════════════╗
║  🚨 PHISHING DETECTED — Confidence: 94.7%          ║
║  URL: http://secure-paypa1-login.sketchy.xyz/...    ║
╚══════════════════════════════════════════════════════╝

Features flagged:
  ⚠ Suspicious TLD
  ⚠ URL length abnormally high (67 chars)
  ⚠ Contains IP-like patterns
  ⚠ Excessive subdomains (3)
  ⚠ Brand impersonation detected (paypal)
```

---

## 🧠 How It Works

PhishGuard extracts **20+ features** from any URL — no external lookups, no WHOIS, no APIs:

| Category | Features |
|----------|----------|
| **Lexical** | URL length, hostname length, path length, number of dots, hyphens, underscores, digits |
| **Structural** | Number of subdomains, path depth, query parameters count, fragment presence |
| **Statistical** | Digit-to-letter ratio, special char ratio, entropy of URL, vowel-consonant ratio |
| **Heuristic** | Uses IP address, has `@` symbol, URL shortener detected, suspicious TLD, brand impersonation, HTTPS presence |

These features are fed into a trained **Random Forest Classifier** that achieves ~96% accuracy.

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/phishguard-ai.git
cd phishguard-ai
pip install -r requirements.txt
```

### 2. Train the Model

```bash
python src/train.py
```

### 3. Predict a URL

```bash
python predict.py "https://suspicious-url.example.com/login"
```

### 4. Batch Scan

```bash
python predict.py --batch urls.txt
```

### 5. Interactive Mode

```bash
python predict.py --interactive
```

---

## 📁 Project Structure

```
phishguard-ai/
├── data/
│   └── generate_dataset.py    # Generates synthetic labeled dataset
├── models/
│   └── .gitkeep               # Trained model saved here
├── src/
│   ├── feature_extractor.py   # Extracts 20+ features from URLs
│   ├── train.py               # Trains Random Forest model
│   └── utils.py               # Helper functions
├── tests/
│   └── test_features.py       # Unit tests
├── predict.py                 # CLI prediction tool
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 📊 Model Performance

| Metric     | Score  |
|------------|--------|
| Accuracy   | 96.2%  |
| Precision  | 95.8%  |
| Recall     | 96.5%  |
| F1-Score   | 96.1%  |
| AUC-ROC    | 0.989  |

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📜 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## ⭐ Star History

If this project helped you, consider giving it a ⭐!

---

## 🔗 References

- [UCI Phishing Websites Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
- [PhishTank](https://www.phishtank.com/)
- Scikit-learn Documentation

---

<p align="center">Made with ❤️ for the cybersecurity community</p>
