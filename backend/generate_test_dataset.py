# generate_test_dataset.py
"""
Generate sample phishing/legitimate dataset để test model training
Sau này bạn có thể replace bằng real data từ WHOIS, phishing URLs database, etc.
"""

import pandas as pd
import os
import numpy as np

BACKEND_DIR = os.path.dirname(__file__)
OUTPUT_PATH = os.path.join(BACKEND_DIR, "Datasets", "dataset_sample.csv")

# Ensure Datasets directory exists
os.makedirs(os.path.join(BACKEND_DIR, "Datasets"), exist_ok=True)

print("Generating sample phishing/legitimate dataset...")

# Legitimate URLs (label = 0)
legitimate_urls = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.python.org",
    "https://www.django-rest-framework.org",
    "https://www.golang.org",
    "https://www.rust-lang.org",
    "https://www.docker.com",
    "https://www.kubernetes.io",
    "https://www.openstack.org",
    "https://www.ubuntu.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    "https://www.twitter.com",
    "https://www.medium.com",
    "https://www.dev.to",
    "https://www.udemy.com",
    "https://www.coursera.org",
    "https://www.edx.org",
] * 4  # Repeat 4 times = 100 URLs

# Phishing URLs (label = 1) - suspicious patterns
phishing_urls = [
    "https://www.gogle.com",  # Typo
    "https://g0ogle.com",  # Zero instead of O
    "https://google-login.xyz",  # Suspicious domain
    "http://192.168.1.1/login",  # IP address
    "https://youttube.com",  # Typo
    "https://facebook-secure-login.xyz/verify",  # Phishing pattern
    "https://amazon-account-verify.tk",  # Free TLD
    "https://www-wikipedia.ml/login",  # Suspicious subdomain
    "https://github-secure.ga/authorize",  # Free TLD
    "http://stackoverflow-help.cf",  # No HTTPS + free TLD
    "https://python-org-verify.xyz/account",  # Typo + suspicious
    "https://django-admin.xyz/login",  # Suspicious
    "https://golang-download.tk/install",  # Free TLD
    "https://rust-lang-compiler.ml",  # Suspicious
    "https://docker-hub-login.ga/auth",  # Free TLD
    "https://kubernetes-admin.xyz",  # Suspicious
    "https://openstack-cloud.cf/login",  # Free TLD
    "https://ubuntu-update.tk",  # Free TLD
    "https://microsoft-account-verify.xyz",  # Phishing pattern
    "https://apple-id-verify.ml/signin",  # Phishing pattern
    "https://linkedin-profile-update.tk",  # Phishing pattern
    "https://instagram-security.ga/confirm",  # Phishing pattern
    "https://twitter-verify-account.xyz",  # Phishing pattern
    "https://medium-membership.cf/upgrade",  # Phishing pattern
    "https://udemy-certificate.ml/download",  # Phishing pattern
    "https://goo.gl/abc123",  # URL shortener
    "https://bit.ly/phishing",  # URL shortener
    "https://tinyurl.com/login",  # URL shortener
] * 4  # Repeat 4 times = 116 URLs

# Create DataFrame
data = {
    'url': legitimate_urls + phishing_urls,
    'label': [0] * len(legitimate_urls) + [1] * len(phishing_urls)
}

df = pd.DataFrame(data)

# Shuffle
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Extract features từ URL (basic feature engineering)
# Note: Train script sẽ extract chi tiết, đây chỉ cho reference

print(f"\nDataset created:")
print(f"  Total samples: {len(df)}")
print(f"  Legitimate (0): {(df['label'] == 0).sum()}")
print(f"  Phishing (1): {(df['label'] == 1).sum()}")
print(f"  Imbalance ratio: {(df['label'] == 0).sum() / (df['label'] == 1).sum():.2f}x")

# Show sample
print(f"\nSample data:")
print(df.head(10).to_string())

# Save
df.to_csv(OUTPUT_PATH, index=False)
print(f"\n✅ Dataset saved to: {OUTPUT_PATH}")
print(f"\n⚠️  This is sample data for testing!")
print(f"    Replace with real phishing URLs from:")
print(f"    - Phishtank.com")
print(f"    - OpenPhish.com")
print(f"    - APWG ecrimes corpus")
print(f"    - Alexa top 1M sites (legitimate)")

print(f"\nNext steps:")
print(f"  1. cp {OUTPUT_PATH} {os.path.join(BACKEND_DIR, 'Datasets', 'dataset.csv')}")
print(f"  2. python train_model.py")
print(f"  3. python predictor_improved.py")
