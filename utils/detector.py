import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

class CloudThreatDetector:
    def __init__(self, contamination=0.08):
        self.model = IsolationForest(
            n_estimators=100, 
            contamination=contamination, 
            random_state=42
        )

    def train(self, X: pd.DataFrame, model_path="models/isolation_forest.pkl"):
        self.model.fit(X)
        joblib.dump(self.model, model_path)

    def load_and_predict(self, X: pd.DataFrame, model_path="models/isolation_forest.pkl") -> pd.Series:
        model = joblib.load(model_path)
        raw_preds = model.predict(X)
        return pd.Series(raw_preds).map({1: 0, -1: 1})