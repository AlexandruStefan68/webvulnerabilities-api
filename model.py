import os
import xgboost as xgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib

folder = './cod_vulnerabil/'  # Asigură-te că folderul există și conține fișierele .c

# Lista de fișiere și etichetele asociate fiecărei vulnerabilități
file_names = [
    ('buffer_overflow.c', 'Buffer Overflow'),
    ('use_after_free.c', 'Use-After-Free'),
    ('double_free.c', 'Double-Free'),
    ('out_of_bounds.c', 'Out-of-Bounds Access'),
    ('heap_spraying.c', 'Heap Spraying')
]

#1. Citirea fișierelor și etichetelor lor
files = []
labels = []

for file_name, label in file_names:
    with open(os.path.join(folder, file_name), 'r') as file:
        code = file.read()  # Citește codul din fișier
        files.append(code)  # Adaugă codul la lista de fișiere
        labels.append(label)  # Adaugă eticheta (tipul vulnerabilității)

# 2. Vectorizarea codului sursă folosind TF-IDF
vectorizer = TfidfVectorizer(stop_words='english')  # Elimină cuvintele de legătură comune
X = vectorizer.fit_transform(files)  # Transformă fișierele în vectori numerici (caracteristici)

# 3. Conversia etichetelor (string -> numerice)
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(labels)  # Convertește etichetele text în numerice

# 4. Împărțirea setului de date în antrenament și test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Antrenarea modelului cu XGBoost
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
model.fit(X_train, y_train)

# 6. Evaluarea modelului
y_pred = model.predict(X_test)
print("Classification Report:\n", classification_report(y_test, y_pred))

# 7. Salvarea modelului antrenat și a vectorizatorului
joblib.dump(model, './models/vulnerability_classifier_xgb.pkl')
joblib.dump(vectorizer, './models/tfidf_vectorizer.pkl')  
joblib.dump(label_encoder, './models/label_encoder.pkl') 
print("Modelul a fost salvat cu succes.")
