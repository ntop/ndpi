import joblib
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, accuracy_score
import time

mlp = joblib.load('mlp_model.joblib')
X_test = joblib.load('X_test.joblib')
y_test = joblib.load('y_test.joblib')
label_encoder = joblib.load('label_encoder.joblib')

# Perform prediction
start = time.time()
y_pred = mlp.predict(X_test)
print(f"Prediction time: {time.time()-start:.2f} seconds")

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, target_names=label_encoder.classes_)

# Print the results
print(f"Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(report)
