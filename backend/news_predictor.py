from nltk.corpus import stopwords
import joblib
import nltk
import re
from nltk.stem.porter import PorterStemmer

ps = PorterStemmer()
nltk.data.path.append('./nltk_data')


model = joblib.load('MLModels\\' + 'fakeNewsModel.pkl')
print('=> Pickle Loaded : Model ')
tfidfvect = joblib.load('MLModels\\' + 'fakeNewsVectorizer.pkl')
print('=> Pickle Loaded : Vectorizer')

# --- BẮT ĐẦU ĐOẠN CODE SOI MODEL ---
try:
    print("\nDang phan tich Model...")
    # 1. Lấy danh sách từ vựng (Do scikit-learn đổi version nên cần check hàm)
    try:
        feature_names = tfidfvect.get_feature_names_out()
    except:
        feature_names = tfidfvect.get_feature_names()

    # 2. Lấy trọng số (coef_)
    # Số CÀNG NHỎ (Âm) = Khả năng cao là FAKE (vì Fake là 0/Class 0)
    # Số CÀNG LỚN (Dương) = Khả năng cao là REAL
    if hasattr(model, 'coef_'):
        coefs = model.coef_[0]
        
        # Ghép từ và điểm số lại
        sorted_zip = sorted(zip(coefs, feature_names))
        
        print("\n=== TOP 20 TỪ MÀ MODEL COI LÀ FAKE (Review Giả) ===")
        # Lấy 20 từ có điểm thấp nhất (đầu danh sách)
        for val, word in sorted_zip[:20]:
            print(f"Từ: '{word}' (Điểm: {val:.3f})")
            
        print("\n=== TOP 20 TỪ MÀ MODEL COI LÀ REAL (Review Thật) ===")
        # Lấy 20 từ có điểm cao nhất (cuối danh sách)
        for val, word in sorted_zip[-20:]:
            print(f"Từ: '{word}' (Điểm: {val:.3f})")
    else:
        print("Model này không phải Linear (có thể là Tree/Forest), không xem được coef_.")
except Exception as e:
    print("Khong the soi model do loi: ", e)
# --- KẾT THÚC ĐOẠN CODE SOI MODEL ---

class PredictionModel:
    output = {}

    # constructor
    def __init__(self, original_text):
        self.output['original'] = original_text


    # predict
    def predict(self):
        review = self.preprocess()
        text_vect = tfidfvect.transform([review]).toarray()
        self.output['prediction'] = 'FAKE' if model.predict(text_vect) == 0 else 'REAL'
        # self.output['prediction'] = model.predict(text_vect) 
        return self.output


    # Helper methods
    def preprocess(self):
        review = re.sub('[^a-zA-Z]', ' ', self.output['original'])
        review = review.lower()
        review = review.split()
        review = [ps.stem(word) for word in review if not word in stopwords.words('english')]
        review = ' '.join(review)
        self.output['preprocessed'] = review
        return review