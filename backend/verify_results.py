import pandas as pd
import numpy as np
import joblib, json, os
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, brier_score_loss

df = pd.read_csv('backend/Datasets/dataset.csv')
drop_cols = [c for c in df.columns if c.startswith('Unnamed') or c == 'index']
df = df.drop(columns=drop_cols, errors='ignore')

print("=== DATASET CHI TIET ===")
print("File: backend/Datasets/dataset.csv")
print(f"Tong so mau: {len(df):,}")
print(f"So features: {df.shape[1]-1}")
print()
raw = df['Result'].value_counts().sort_index()
print("Phan phoi nhan (RAW encoding cua paper):")
print(f"  Result = -1 (Phishing trong paper goc) : {raw.get(-1,0):,}")
print(f"  Result =  1 (Legitimate trong paper goc): {raw.get(1,0):,}")
print()
print("DIEM QUAN TRONG:")
print("  - Day la dataset da DUOC ENCODE TRUOC (not raw URLs)")
print("  - Moi feature la ternary {-1, 0, 1} theo paper Mohammad 2015")
print("  - Khong co raw URL string, khong co HTML, chi co numbers")
print("  - Nguon: UCI ML Repository, 2015 (9 nam tuoi!)")

df['Result'] = df['Result'].map({-1: 1, 1: 0})
X = df.drop(columns=['Result'])
y = df['Result']
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print()
print("=== TRAIN/TEST SPLIT ===")
print(f"Train: {len(X_train):,} mau (80%)")
print(f"Test : {len(X_test):,} mau (20%)")
print(f"Phuong phap: Stratified random split (random_state=42)")
print()
print(f"Train - Phishing: {y_train.sum():,} ({y_train.mean()*100:.1f}%)")
print(f"Train - Legit   : {(y_train==0).sum():,} ({(y_train==0).mean()*100:.1f}%)")
print(f"Test  - Phishing: {y_test.sum():,} ({y_test.mean()*100:.1f}%)")
print(f"Test  - Legit   : {(y_test==0).sum():,} ({(y_test==0).mean()*100:.1f}%)")

# Model sizes
rf_path = 'backend/MLModels/phishing_rf_model_tuned.pkl'
xgb_path = 'backend/MLModels/phishing_xgb_calibrated.pkl'
print()
print("=== MODEL SIZE ===")
if os.path.exists(rf_path):
    print(f"RF  v1.0: {os.path.getsize(rf_path)/1024/1024:.1f} MB")
if os.path.exists(xgb_path):
    print(f"XGB v2.0: {os.path.getsize(xgb_path)/1024/1024:.1f} MB")

# Optimal threshold
with open('backend/MLModels/optimal_threshold.json') as f:
    t = json.load(f)
print()
print("=== OPTIMAL THRESHOLD ===")
print(f"Value : {t['optimal_threshold']}")
print(f"Method: {t['method']}")

# Re-evaluate model on test set to confirm numbers
print()
print("=== XAC NHAN KET QUA TREN TEST SET ===")
model = joblib.load(xgb_path)
feat = joblib.load('backend/MLModels/phishing_xgb_features.pkl')
X_test_df = pd.DataFrame(X_test.values, columns=feat)
y_proba = model.predict_proba(X_test_df)[:, 1]
threshold = t['optimal_threshold']
y_pred = (y_proba >= threshold).astype(int)

print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()
print(f"Confusion Matrix:")
print(f"  TN (legit doan dung)       = {tn}")
print(f"  FP (legit bi block nham)   = {fp}   << chi {fp} trong {tn+fp} URL hop le bi nham")
print(f"  FN (phishing bo sot)       = {fn}   << {fn} trong {tn+fp+fn+tp} URL phishing bi bo qua")
print(f"  TP (phishing phat hien dung) = {tp}")
print()
print(f"ROC-AUC    = {roc_auc_score(y_test, y_proba):.4f}")
print(f"Brier Score = {brier_score_loss(y_test, y_proba):.4f}  (0=perfect, 0.25=random)")
print(f"FPR        = {fp/(fp+tn)*100:.2f}%  ({fp}/{tn+fp} legit URL bi block nham)")
print(f"FNR        = {fn/(fn+tp)*100:.2f}%  ({fn}/{fn+tp} phishing bi bo sot)")
