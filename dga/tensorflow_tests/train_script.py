import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense
import pandas as pd
import joblib

# Check if GPU is available
gpus = tf.config.list_physical_devices('GPU')
if gpus:
    print(f"Num GPUs Available: {len(gpus)}")
    for gpu in gpus:
        print(f"GPU: {gpu}")
else:
    print("No GPUs available. Using CPU.")

# Read the file
df = pd.read_csv("../dga_domains_full.csv", header=None, names=["label", "family", "domain"])
df = df[["label", "domain"]]

# Transform labels (legit/dga) into numbers
label_encoder = LabelEncoder()
df["label_encoded"] = label_encoder.fit_transform(df["label"])

# Pre-process domains
tokenizer = Tokenizer(char_level=True)  # Character-level tokenization
tokenizer.fit_on_texts(df["domain"])
sequences = tokenizer.texts_to_sequences(df["domain"])
X = pad_sequences(sequences, maxlen=100)  # Padding for maximum length
y = df["label_encoded"].values

# Split the dataset into train, validation, and test sets
X_temp, X_test, y_temp, y_test = train_test_split(X, df["label_encoded"], test_size=0.1, random_state=27)
X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.1, random_state=27)  # 10% of 90% is 9%, resulting in 81% train, 9% validation, 10% test

# Model with embedding
model = Sequential()
model.add(Embedding(input_dim=len(tokenizer.word_index)+1, output_dim=50, input_length=100))  # Embedding
model.add(LSTM(64))  # Recurrent layer
model.add(Dense(1, activation='sigmoid'))

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

import time

start = time.time()
with tf.device('/GPU:0' if gpus else '/CPU:0'):
    model.fit(X_train, y_train, epochs=5, batch_size=32, validation_data=(X_val, y_val))
print(f"Training time: {time.time() - start}")

# Make predictions on the test set
y_pred = (model.predict(X_test) > 0.5).astype("int32").flatten()

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")

# Generate the classification report
report = classification_report(y_test, y_pred, target_names=label_encoder.classes_)
print("\nClassification Report:")
print(report)

# Save model, test dataset and tensorflow utilities for future test
model.save("dga_model.keras")
joblib.dump((X_test, y_test), "test_data.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
joblib.dump(tokenizer, "tokenizer.pkl")
