# Contributing to PhishGuard AI

Thanks for your interest in contributing! Here's how to get started.

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/phishguard-ai.git
cd phishguard-ai
pip install -r requirements.txt
python src/train.py  # Train the model
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Adding New Features

1. Add feature extraction logic in `src/feature_extractor.py`
2. Add corresponding tests in `tests/test_features.py`
3. Retrain the model with `python src/train.py`
4. Verify accuracy hasn't dropped

## Pull Request Process

1. Fork the repo and create your branch from `main`
2. Add tests for any new features
3. Ensure all tests pass
4. Update README if needed
5. Submit your PR with a clear description

## Ideas for Contribution

- Add more URL feature extractors
- Improve dataset generation with more patterns
- Add a web UI (Flask/Streamlit)
- Support real phishing datasets (PhishTank CSV)
- Add visualization of feature importance
- Docker support
- Browser extension integration
