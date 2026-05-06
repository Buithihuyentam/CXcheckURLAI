import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# 1. Đọc dữ liệu từ file bạn vừa tải
df = pd.read_csv('../Datasets/dataset.csv')

# 2. Chuẩn bị dữ liệu (Bỏ cột ID và lấy cột nhãn 'Result')
X = df.drop(['index', 'Result'], axis=1)
y = df['Result']

# 3. Chia tập Train/Test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Khởi tạo mô hình Random Forest (Mô hình tốt nhất trong bài báo)
model = RandomForestClassifier(n_estimators=100, random_state=42)

# 5. Huấn luyện (Chỉ mất vài giây)
model.fit(X_train, y_train)

# 6. Kiểm tra độ chính xác
y_pred = model.predict(X_test)
print(f"Độ chính xác: {accuracy_score(y_test, y_pred)*100:.2f}%")

# 7. Lưu mô hình để dùng cho dự án
import joblib
joblib.dump(model, 'phishing_rf_model.pkl')