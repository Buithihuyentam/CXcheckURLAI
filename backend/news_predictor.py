from nltk.corpus import stopwords
import joblib
import nltk
import re
from nltk.stem.porter import PorterStemmer

ps = PorterStemmer()
nltk.data.path.append('./nltk_data')



phish_path = joblib.load('MLModels\\' + 'phishing.pkl')
print('=> Pickle Loaded : Phishing Model')
# --- BẮT ĐẦU ĐOẠN CODE SOI MODEL ---

    print("\n--- SOARING PHISHING MODEL ---")
    if hasattr(phish_path, 'feature_importances_'):
        print("Trong so cac dac trung (Feature Importances):")
        importances = phish_path.feature_importances_
        for i, v in enumerate(importances):
            print(f"  Dac trung {i}: {v:.4f}")
    else:
        print("Model phishing khong co feature_importances_")
except Exception as e:
    print("Khong the soi model do loi: ", e)
