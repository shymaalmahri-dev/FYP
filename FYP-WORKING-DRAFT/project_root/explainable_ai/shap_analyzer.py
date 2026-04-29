import json
import os
from pathlib import Path

import joblib
import pandas as pd
import shap

print("[SHAP] Initializing SHAP Explainability Engine...")

BASE_DIR = Path(__file__).resolve().parent


def resolve_model_dir():
    candidates = []

    env_dir = os.environ.get("ELAI_SHAP_ARTIFACT_DIR", "").strip()
    if env_dir:
        candidates.append(Path(env_dir))

    candidates.append(BASE_DIR / "model_artifacts")
    candidates.append(BASE_DIR.parent / "FYP" / "edge_ai_artifacts")

    for candidate in candidates:
        if (
            (candidate / "rf_model.joblib").exists()
            and (candidate / "scaler.joblib").exists()
            and (candidate / "feature_columns.joblib").exists()
        ):
            return candidate

    return candidates[0]


MODEL_DIR = resolve_model_dir()

MODEL_PATH = MODEL_DIR / "rf_model.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
FEATURE_PATH = MODEL_DIR / "feature_columns.joblib"

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_columns = joblib.load(FEATURE_PATH)

    print(f"[SHAP] Model loaded successfully from {MODEL_DIR}.")
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
