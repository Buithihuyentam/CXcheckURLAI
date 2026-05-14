"""
download_phiusiil.py
====================
Download PhiUSIIL dataset (2023, 235,795 URLs) từ UCI ML Repository.

Citation:
  Prasad, A. & Chandra, S. (2024).
  PhiUSIIL Phishing URL (Website) [Dataset].
  UCI Machine Learning Repository.
  DOI: 10.1016/j.cose.2023.103545

Chạy một lần: python backend/download_phiusiil.py
"""

import os
import pandas as pd
from ucimlrepo import fetch_ucirepo

OUT_DIR  = os.path.join(os.path.dirname(__file__), "Datasets")
OUT_PATH = os.path.join(OUT_DIR, "phiusiil_2023.csv")

def main():
    if os.path.exists(OUT_PATH):
        print(f"[!] Da ton tai: {OUT_PATH}")
        df = pd.read_csv(OUT_PATH)
        print(f"    Shape: {df.shape}")
        print(f"    Columns: {df.columns.tolist()[:10]} ...")
        return

    print("[+] Downloading PhiUSIIL dataset (id=967) tu UCI...")
    print("    235,795 URLs x 54 features — co the mat 1-3 phut...")

    ds = fetch_ucirepo(id=967)
    X  = ds.data.features
    y  = ds.data.targets

    print(f"\n[+] Features shape : {X.shape}")
    print(f"[+] Target shape   : {y.shape}")
    print(f"[+] Target column  : {y.columns.tolist()}")
    print(f"[+] Target values  : {y.iloc[:,0].value_counts().to_dict()}")
    print()
    print("[+] Features (54):")
    for i, col in enumerate(X.columns):
        print(f"  {i+1:2d}. {col}")

    # Gop X va y thanh 1 file
    df = pd.concat([X, y], axis=1)
    os.makedirs(OUT_DIR, exist_ok=True)
    df.to_csv(OUT_PATH, index=False)
    print(f"\n[OK] Saved: {OUT_PATH}")
    print(f"     Shape: {df.shape}")
    print(f"     Size : {os.path.getsize(OUT_PATH)/1024/1024:.1f} MB")

if __name__ == "__main__":
    main()
