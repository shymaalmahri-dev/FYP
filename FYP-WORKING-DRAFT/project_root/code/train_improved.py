import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils import shuffle
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# ── 1. LOAD AND SHUFFLE ──────────────────────────────────────
print("[*] Loading dataset...")
df = pd.read_csv('training_data_iot.csv')
df = shuffle(df, random_state=42).reset_index(drop=True)
print(f"[*] Total rows: {len(df)}")
print(df['label'].value_counts())

# ── 2. BALANCE CLASSES ───────────────────────────────────────
# Cap each class at 3x the smallest class to reduce bias
min_count = df['label'].value_counts().min()
max_allowed = min_count * 3
balanced_parts = []
for lbl, group in df.groupby('label'):
    balanced_parts.append(group.sample(min(len(group), max_allowed), random_state=42))
df_balanced = shuffle(pd.concat(balanced_parts), random_state=42).reset_index(drop=True)
print(f"\n[*] After balancing: {df_balanced['label'].value_counts().to_dict()}")

X = df_balanced.drop('label', axis=1)
y = df_balanced['label']

le = LabelEncoder()
y_encoded = le.fit_transform(y)
feature_columns = X.columns.tolist()
print(f"[*] Classes: {list(le.classes_)}")
print(f"[*] Features: {len(feature_columns)}")

# ── 3. SCALE ─────────────────────────────────────────────────
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ── 4. 5-FOLD CROSS-VALIDATION ───────────────────────────────
print("\n[*] Running 5-fold cross-validation...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=5,
    min_samples_split=10,
    class_weight='balanced',   # handles remaining imbalance
    random_state=42,
    n_jobs=-1
)

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_results = cross_validate(rf, X_scaled, y_encoded, cv=cv,
    scoring=['accuracy', 'f1_macro', 'roc_auc_ovr'],
    return_train_score=True)

print("\n--- Cross-Validation Results ---")
print(f"Accuracy : {cv_results['test_accuracy'].mean():.4f} ± {cv_results['test_accuracy'].std():.4f}")
print(f"F1 Macro : {cv_results['test_f1_macro'].mean():.4f} ± {cv_results['test_f1_macro'].std():.4f}")
print(f"ROC AUC  : {cv_results['test_roc_auc_ovr'].mean():.4f} ± {cv_results['test_roc_auc_ovr'].std():.4f}")
print(f"Train Acc: {cv_results['train_accuracy'].mean():.4f}  (check for overfit - should be close to test)")

# ── 5. FINAL TRAIN / TEST SPLIT ──────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, stratify=y_encoded, random_state=42)

rf.fit(X_train, y_train)

# ── 6. EVALUATE ──────────────────────────────────────────────
y_pred = rf.predict(X_test)
y_proba = rf.predict_proba(X_test)

print("\n--- Hold-out Test Set Performance ---")
print(classification_report(y_test, y_pred, target_names=le.classes_, digits=4))

print("Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print("Labels:", list(le.classes_))
print(cm)

print("\n--- Per-Class FP / FN ---")
for i, cls in enumerate(le.classes_):
    tp=cm[i][i]; fn=cm[i].sum()-tp; fp=cm[:,i].sum()-tp; tn=cm.sum()-tp-fn-fp
    fpr=fp/(fp+tn) if (fp+tn)>0 else 0
    fnr=fn/(fn+tp) if (fn+tp)>0 else 0
    print(f"  {cls}: FPR={fpr:.4f}  FNR={fnr:.4f}  FP={fp}  FN={fn}")

auc = roc_auc_score(y_test, y_proba, multi_class='ovr', average='macro')
print(f"\nROC AUC (macro): {auc:.4f}")

print("\n--- Feature Importances ---")
fi = sorted(zip(feature_columns, rf.feature_importances_), key=lambda x: x[1], reverse=True)
for fname, imp in fi[:10]:
    print(f"  {fname}: {imp:.4f}")

# ── 7. SAVE ARTIFACTS ────────────────────────────────────────
os.makedirs('edge_ai_artifacts', exist_ok=True)
joblib.dump(rf,             'edge_ai_artifacts/rf_model.joblib')
joblib.dump(scaler,         'edge_ai_artifacts/scaler.joblib')
joblib.dump(le,             'edge_ai_artifacts/label_encoder.joblib')
joblib.dump(feature_columns,'edge_ai_artifacts/feature_columns.joblib')
print("\n[!] All artifacts saved to edge_ai_artifacts/")