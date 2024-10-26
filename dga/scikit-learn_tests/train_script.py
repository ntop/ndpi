from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.decomposition import TruncatedSVD
import pandas as pd
import time
import joblib

df = pd.read_csv("../dga_domains_full.csv", header=None, names=["label", "family", "domain"])
df = df[["label", "domain"]]

# Label Encoding and Domain Vectorization Representation
label_encoder = LabelEncoder()
df["label_encoded"] = label_encoder.fit_transform(df["label"])
vectorizer = CountVectorizer(analyzer='char_wb', ngram_range=(2, 4))  # Use 2 to 4 character n-grams
X = vectorizer.fit_transform(df["domain"])
joblib.dump(label_encoder, "label_encoder.joblib")

# Dimensionality Reduction
svd = TruncatedSVD(n_components=100)  # Set the number of components as needed
X_reduced = svd.fit_transform(X)

# Suddividere il dataset in training e test
X_train, X_test, y_train, y_test = train_test_split(X_reduced, df["label_encoded"], test_size=0.1, shuffle=True, random_state=27)
joblib.dump(X_test, "X_test.joblib")
joblib.dump(y_test, "y_test.joblib")

# Inizializzazione e addestramento
mlp = MLPClassifier(hidden_layer_sizes=(100,), max_iter=300, random_state=27)

start = time.time()
mlp.fit(X_train, y_train)
print(f"Tempo di addestramento: {time.time()-start:.2f} secondi")

# Fare previsioni sul set di test
start = time.time()
y_pred = mlp.predict(X_test)
print(f"Tempo di previsione: {time.time()-start:.2f} secondi")

# Valutare le prestazioni del modello
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, target_names=label_encoder.classes_)

# Stampa i risultati
print(f"Accuratezza: {accuracy:.4f}")
print("\nClassification Report:")
print(report)
joblib.dump(mlp, 'mlp_model.joblib')