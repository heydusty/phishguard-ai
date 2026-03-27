"""
PhishGuard AI — Synthetic Dataset Generator
Generates a labeled dataset of phishing and legitimate URLs for training.
No external downloads required.
"""

import csv
import random
import string
import os

# ── Legitimate URL patterns ──────────────────────────────

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
    "reddit.com", "netflix.com", "microsoft.com", "apple.com",
    "github.com", "stackoverflow.com", "medium.com", "quora.com",
    "bbc.com", "cnn.com", "nytimes.com", "reuters.com",
    "shopify.com", "stripe.com", "zoom.us", "slack.com",
    "notion.so", "figma.com", "vercel.app", "heroku.com",
    "cloudflare.com", "digitalocean.com", "aws.amazon.com",
    "docs.google.com", "drive.google.com", "mail.google.com",
    "outlook.com", "office.com", "adobe.com", "canva.com",
    "spotify.com", "twitch.tv", "discord.com", "telegram.org",
]

LEGIT_PATHS = [
    "/", "/about", "/contact", "/login", "/signup", "/pricing",
    "/blog", "/news", "/help", "/support", "/docs", "/api",
    "/products", "/services", "/careers", "/team", "/faq",
    "/search", "/settings", "/profile", "/dashboard",
    "/terms", "/privacy", "/security",
]

# ── Phishing URL patterns ────────────────────────────────

PHISH_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".club", ".icu", ".site", ".online"]
PHISH_BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "chase", "wellsfargo", "instagram"]
PHISH_WORDS = ["secure", "verify", "account", "login", "update", "confirm", "banking", "alert", "suspend", "unlock", "validate", "restore"]
PHISH_SEPARATORS = ["-", ".", ""]


def random_string(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def generate_legit_url():
    """Generate a realistic legitimate URL."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    
    # Sometimes add query params
    query = ""
    if random.random() < 0.3:
        query = f"?q={random_string(5)}"
    if random.random() < 0.2:
        query += f"&page={random.randint(1, 10)}"
    
    scheme = "https"
    return f"{scheme}://{domain}{path}{query}"


def generate_phishing_url():
    """Generate a realistic phishing URL."""
    strategies = [
        _phish_brand_impersonation,
        _phish_ip_address,
        _phish_long_subdomain,
        _phish_misspelling,
        _phish_keyword_stuffing,
        _phish_random_domain,
    ]
    return random.choice(strategies)()


def _phish_brand_impersonation():
    brand = random.choice(PHISH_BRANDS)
    word = random.choice(PHISH_WORDS)
    sep = random.choice(PHISH_SEPARATORS)
    tld = random.choice(PHISH_TLDS)
    scheme = random.choice(["http", "https"])
    path = random.choice(["/login", "/verify", "/account", "/update", f"/{random_string(6)}"])
    return f"{scheme}://{word}{sep}{brand}{sep}{random_string(4)}{tld}{path}"


def _phish_ip_address():
    ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
    path = random.choice(["/login.php", "/admin/", f"/{random_string(8)}.html", "/wp-login.php"])
    port = random.choice(["", ":8080", ":8443", ":3000"])
    return f"http://{ip}{port}{path}"


def _phish_long_subdomain():
    brand = random.choice(PHISH_BRANDS)
    words = random.sample(PHISH_WORDS, k=random.randint(2, 4))
    subdomain = "-".join(words)
    tld = random.choice(PHISH_TLDS)
    return f"http://{brand}.{subdomain}.{random_string(6)}{tld}/login"


def _phish_misspelling():
    misspellings = {
        "paypal": ["paypa1", "paypai", "paypaI", "paypol", "peypal"],
        "google": ["g00gle", "googIe", "gooogle", "googel", "g0ogle"],
        "apple": ["app1e", "appie", "appIe", "aple", "applle"],
        "amazon": ["amaz0n", "arnazon", "amazom", "armazon"],
        "microsoft": ["micr0soft", "mircosoft", "microsft", "mlcrosoft"],
    }
    brand = random.choice(list(misspellings.keys()))
    misspelled = random.choice(misspellings[brand])
    tld = random.choice(PHISH_TLDS + [".com", ".net"])
    return f"https://{misspelled}-{random.choice(PHISH_WORDS)}{tld}/login"


def _phish_keyword_stuffing():
    words = random.sample(PHISH_WORDS, k=random.randint(3, 5))
    tld = random.choice(PHISH_TLDS)
    path = "/" + "/".join(random.sample(PHISH_WORDS, k=2))
    query = f"?token={random_string(16)}&id={random.randint(10000, 99999)}"
    return f"http://{'-'.join(words)}{tld}{path}{query}"


def _phish_random_domain():
    domain = random_string(random.randint(10, 20))
    tld = random.choice(PHISH_TLDS)
    path = f"/{random.choice(PHISH_BRANDS)}/{random.choice(PHISH_WORDS)}"
    return f"http://{domain}{tld}{path}"


def generate_dataset(n_samples=5000, output_path="data/dataset.csv"):
    """Generate a balanced dataset of phishing and legitimate URLs."""
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    data = []
    
    # Generate legitimate URLs
    for _ in range(n_samples // 2):
        data.append({"url": generate_legit_url(), "label": 0})
    
    # Generate phishing URLs
    for _ in range(n_samples // 2):
        data.append({"url": generate_phishing_url(), "label": 1})
    
    # Shuffle
    random.shuffle(data)
    
    # Write CSV
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(data)
    
    print(f"✅ Dataset generated: {output_path}")
    print(f"   Total samples: {len(data)}")
    print(f"   Legitimate: {sum(1 for d in data if d['label'] == 0)}")
    print(f"   Phishing:   {sum(1 for d in data if d['label'] == 1)}")
    
    return output_path


if __name__ == "__main__":
    generate_dataset()
