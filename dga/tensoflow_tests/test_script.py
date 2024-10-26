import tensorflow as tf
import joblib
import numpy as np
from sklearn.metrics import classification_report, accuracy_score

# Load the model
model = tf.keras.models.load_model("dga_model.keras")
X_test, y_test = joblib.load("test_data.pkl")
label_encoder = joblib.load("label_encoder.pkl")
tokenizer = joblib.load("tokenizer.pkl")

# Make predictions on the test set
y_pred = (model.predict(X_test) > 0.5).astype("int32").flatten()

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")

# Generate the classification report
report = classification_report(y_test, y_pred, target_names=label_encoder.classes_)
print("\nClassification Report:")
print(report)
