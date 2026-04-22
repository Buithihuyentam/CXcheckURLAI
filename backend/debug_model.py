import joblib
import pandas as pd

# 1. Load model
model1 = joblib.load('MLModels/phishing.pkl')

print("--- DANG GIAI MA PHISHING.PKL ---")

try:
    # 2. Truy cập chính xác vào các bước của Pipeline dựa trên dict_keys bạn đã gửi
    vectorizer = model1.named_steps['countvectorizer']
    classifier = model1.named_steps['logisticregression']

    # 3. Lấy danh sách từ vựng (features)
    # Vì bạn dùng sklearn 1.8.0 (bản mới), ta dùng get_feature_names_out()
    try:
        feature_names = vectorizer.get_feature_names_out()
    except:
        feature_names = vectorizer.get_feature_names()

    # 4. Lấy trọng số (Coefficients)
    coefs = classifier.coef_[0]

    # 5. Tạo DataFrame để dễ quan sát
    df = pd.DataFrame({'Dấu hiệu': feature_names, 'Trọng số': coefs})

    # --- KẾT QUẢ ---

    # Trọng số DƯƠNG (+) càng cao = Càng giống Phishing
    print("\n=== TOP 20 DẤU HIỆU ĐẶC TRƯNG CỦA LINK LỪA ĐẢO (PHISHING) ===")
    phishing_signs = df.sort_values(by='Trọng số', ascending=False).head(20)
    print(phishing_signs)

    # Trọng số ÂM (-) càng thấp = Càng giống Link an toàn
    print("\n=== TOP 20 DẤU HIỆU ĐẶC TRƯNG CỦA LINK AN TOÀN (SAFE) ===")
    safe_signs = df.sort_values(by='Trọng số', ascending=True).head(20)
    print(safe_signs)

except Exception as e:
    print(f"Lỗi phát sinh: {e}")