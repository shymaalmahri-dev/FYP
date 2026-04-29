import shap
import joblib
import pandas as pd
import os
import json

print("[SHAP] Initializing SHAP Explainability Engine...")

BASE_DIR = os.path.dirname(__file__)
MODEL_DIR = os.path.join(BASE_DIR, "model_artifacts")

MODEL_PATH = os.path.join(MODEL_DIR, "rf_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
FEATURE_PATH = os.path.join(MODEL_DIR, "feature_columns.joblib")

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_columns = joblib.load(FEATURE_PATH)

    print(f"[SHAP] Model loaded successfully.")
    print(f"[SHAP] Feature count: {len(feature_columns)}")

except Exception as e:
    print("[SHAP] ERROR loading model artifacts:", e)
    raise

print("[SHAP] Building SHAP TreeExplainer...")
explainer = shap.TreeExplainer(model)

def explain_prediction(feature_dict):

    try:
        df = pd.DataFrame([feature_dict])

        df = df[feature_columns]

        scaled = scaler.transform(df)

        shap_values = explainer.shap_values(scaled)

        # Normalize SHAP output for different SHAP versions and model shapes
        if hasattr(shap_values, "values"):
            shap_values = shap_values.values

        if isinstance(shap_values, list):
            if len(shap_values) > 1:
                shap_values = shap_values[1]
            else:
                shap_values = shap_values[0]

        if hasattr(shap_values, "ndim"):
            if shap_values.ndim == 3:
                # Use the class with largest total absolute impact.
                class_idx = int((abs(shap_values[0]).sum(axis=0)).argmax())
                contributions = shap_values[0][:, class_idx]
            elif shap_values.ndim == 2:
                contributions = shap_values[0]
            elif shap_values.ndim == 1:
                contributions = shap_values
            else:
                raise ValueError(f"Unexpected SHAP values ndim: {shap_values.ndim}")
        else:
            contributions = shap_values[0]

        feature_importance = []

        for i, val in enumerate(contributions):
            feature_importance.append({
                "feature": feature_columns[i],
                "impact": float(val)
            })

        feature_importance.sort(
            key=lambda x: abs(x["impact"]),
            reverse=True
        )

        top_features = feature_importance[:5]

        print("[SHAP] Explanation generated.")

        return top_features

    except Exception as e:

        print("[SHAP] ERROR generating explanation:", e)
        return []