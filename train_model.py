print("Training script started...")
import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle

df = pd.read_csv('transactions.csv')
df['label'] = df['label'].apply(lambda x: -1 if x == 'fraud' else 1)

features = df[['amount', 'time_score', 'location_score']]
model = IsolationForest()
model.fit(features)

with open('fraud_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("✅ Model trained and saved as fraud_model.pkl")
print("Model training complete. Model saved as model.pkl.")
