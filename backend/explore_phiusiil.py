"""
explore_phiusiil.py — Khao sat dataset PhiUSIIL 2023
Tim hieu features co the dung de retrain
"""
import pandas as pd
import numpy as np

df = pd.read_csv('backend/Datasets/phiusiil_2023.csv')
old = pd.read_csv('backend/Datasets/dataset.csv')

print("=== PHIUSIIL 2023 ===")
print(f"Shape  : {df.shape}")
print(f"Labels : {df['label'].value_counts().to_dict()}")
print(f"  1 = Legitimate : {(df['label']==1).sum():,} ({(df['label']==1).mean()*100:.1f}%)")
print(f"  0 = Phishing   : {(df['label']==0).sum():,} ({(df['label']==0).mean()*100:.1f}%)")
print()
print(f"Has raw URL string : YES — column 'URL'")
print(f"Has raw Domain     : YES — column 'Domain'")
print(f"Feature types      : mostly continuous/integer (NOT ternary!)")
print()

# Kiem tra cac feature quan trong
key_feats = ['URLLength','IsDomainIP','NoOfSubDomain','IsHTTPS',
             'NoOfURLRedirect','HasObfuscation','TLDLegitimateProb',
             'URLSimilarityIndex','DomainTitleMatchScore','HasPasswordField',
             'NoOfiFrame','HasExternalFormSubmit','URLCharProb']
print("=== SAMPLE FEATURE VALUES ===")
print(df[key_feats].describe().round(3).to_string())
print()

print("=== SO SANH VOI DATASET CU ===")
drop_old = [c for c in old.columns if c.startswith('Unnamed') or c=='index']
old = old.drop(columns=drop_old, errors='ignore')
print(f"Dataset cu (2015)  : {old.shape[0]:,} mau x {old.shape[1]-1} features (ternary {{-1,0,1}})")
print(f"Dataset moi (2023) : {df.shape[0]:,} mau x {df.shape[1]-1} features (continuous)")
print()
print("PHAT HIEN QUAN TRONG:")
print("  - PhiUSIIL dung continuous features, KHONG phai ternary")
print("  - Co URL raw -> co the extract them features moi")
print("  - 54 features vs 30 features cu")
print()
print("  Chien luoc ghep dataset:")
print("  Option A: Chi dung PhiUSIIL (235K, 2023) — thay hoan toan dataset cu")
print("  Option B: Dung ca hai (kem) — NGUY HIEM vi encoding khac nhau")
print("  => KHUYEN NGHI: Option A — chi dung PhiUSIIL")
print()

# Tim features co the map giua hai dataset
print("=== MAPPING FEATURES GAN GIONG ===")
mapping = {
    'URLLength'      : 'URLURL_Length (encoded)',
    'IsDomainIP'     : 'having_IPhaving_IP_Address',
    'IsHTTPS'        : 'SSLfinal_State',
    'NoOfURLRedirect': 'Redirect',
    'NoOfiFrame'     : 'Iframe',
    'HasExternalFormSubmit': 'SFH',
    'NoOfSubDomain'  : 'having_Sub_Domain',
}
for new_f, old_f in mapping.items():
    # Stats for new dataset
    s = df[new_f].describe()
    phish_mean = df[df['label']==0][new_f].mean()
    legit_mean = df[df['label']==1][new_f].mean()
    print(f"  {new_f:<30} phishing_mean={phish_mean:.3f}  legit_mean={legit_mean:.3f}  -> maps to old: {old_f}")
