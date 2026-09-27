import json
import os
import pickle
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder

# ============================================================
# ETAPE 1 - Chargement du dataset brut Wazuh
# ============================================================
print("Chargement du dataset...")

rows = []
DATASET_PATH = os.environ.get("TRAINING_DATASET", "dataset_ia.jsonl")
MODEL_OUTPUT = os.environ.get("MODEL_OUTPUT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "model_extended.pkl"))

with open(DATASET_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue

print(f"Nombre total d'alertes chargees : {len(rows)}")

def safe_get(d, path, default=None):
    cur = d
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur

records = []
for r in rows:
    label = safe_get(r, "data.alert.signature", "UNKNOWN")
    record = {
        "label": label,
        "severity": safe_get(r, "data.alert.severity", "0"),
        "proto": safe_get(r, "data.proto", "UNKNOWN"),
        "dest_port": safe_get(r, "data.dest_port", "0"),
        "src_port": safe_get(r, "data.src_port", "0"),
        "action": safe_get(r, "data.alert.action", "unknown"),
        "category": safe_get(r, "data.alert.category", "unknown"),
        "pkts_toserver": safe_get(r, "data.flow.pkts_toserver", "0"),
        "pkts_toclient": safe_get(r, "data.flow.pkts_toclient", "0"),
        "bytes_toserver": safe_get(r, "data.flow.bytes_toserver", "0"),
        "bytes_toclient": safe_get(r, "data.flow.bytes_toclient", "0"),
        "direction": safe_get(r, "data.direction", "unknown"),
        "rule_level": safe_get(r, "rule.level", 0),
        "firedtimes": safe_get(r, "rule.firedtimes", 0),
    }
    records.append(record)

df = pd.DataFrame(records)
print("Apercu du dataset construit :")
print(df.head())
print("\nDistribution des labels (types d'attaques) :")
print(df["label"].value_counts())

num_cols = ["severity", "dest_port", "src_port", "pkts_toserver",
            "pkts_toclient", "bytes_toserver", "bytes_toclient",
            "rule_level", "firedtimes"]
for col in num_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

cat_cols = ["proto", "action", "category", "direction"]
df_encoded = pd.get_dummies(df, columns=cat_cols)

le = LabelEncoder()
df_encoded["label_encoded"] = le.fit_transform(df_encoded["label"])

feature_cols = [c for c in df_encoded.columns if c not in ["label", "label_encoded"]]
X = df_encoded[feature_cols]
y = df_encoded["label_encoded"]

print(f"\nNombre de features utilisees : {len(feature_cols)}")
print(f"Nombre de classes (types d'attaques) : {len(le.classes_)}")
print("Classes :", list(le.classes_))

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain : {X_train.shape[0]} alertes | Test : {X_test.shape[0]} alertes")

print("\n=== RANDOM FOREST ===")
rf = RandomForestClassifier(n_estimators=200, random_state=42)
rf.fit(X_train, y_train)
y_pred_rf = rf.predict(X_test)

acc_rf = accuracy_score(y_test, y_pred_rf)
print(f"Accuracy Random Forest : {acc_rf:.4f}")
print("\nClassification report (Random Forest) :")
print(classification_report(y_test, y_pred_rf, target_names=le.classes_, zero_division=0))

cm = confusion_matrix(y_test, y_pred_rf)
plt.figure(figsize=(10, 8))
plt.imshow(cm, interpolation="nearest", cmap="Blues")
plt.colorbar()
plt.xlabel("Predit")
plt.ylabel("Reel")
plt.title("Matrice de confusion - Random Forest")
tick_marks = np.arange(len(le.classes_))
plt.xticks(tick_marks, le.classes_, rotation=45, ha="right")
plt.yticks(tick_marks, le.classes_)

thresh = cm.max() / 2.0
for i in range(cm.shape[0]):
    for j in range(cm.shape[1]):
        plt.text(j, i, format(cm[i, j], "d"),
                  ha="center", va="center",
                  color="white" if cm[i, j] > thresh else "black")

plt.tight_layout()
plt.savefig("confusion_matrix_rf.png", dpi=150)
print("\nMatrice de confusion sauvegardee : confusion_matrix_rf.png")

print("\n=== GRADIENT BOOSTING ===")
gb_model = GradientBoostingClassifier(n_estimators=200, random_state=42)
gb_model.fit(X_train, y_train)
y_pred_gb = gb_model.predict(X_test)

acc_gb = accuracy_score(y_test, y_pred_gb)
print(f"Accuracy Gradient Boosting : {acc_gb:.4f}")
print("\nClassification report (Gradient Boosting) :")
print(classification_report(y_test, y_pred_gb, target_names=le.classes_, zero_division=0))

print(f"\nComparaison finale -> Random Forest : {acc_rf:.4f} | Gradient Boosting : {acc_gb:.4f}")

importances = pd.Series(rf.feature_importances_, index=feature_cols)
importances = importances.sort_values(ascending=False).head(15)

plt.figure(figsize=(10, 6))
importances.plot(kind="barh")
plt.gca().invert_yaxis()
plt.xlabel("Importance")
plt.title("Top 15 features les plus importantes - Random Forest")
plt.tight_layout()
plt.savefig("feature_importance.png", dpi=150)
print("\nGraphique feature importance sauvegarde : feature_importance.png")
print(importances)

bundle = {
    "model": rf,
    "label_encoder": le,
    "feature_cols": feature_cols,
    "num_cols": num_cols,
    "cat_cols": cat_cols,
}
os.makedirs(os.path.dirname(MODEL_OUTPUT), exist_ok=True)
with open(MODEL_OUTPUT, "wb") as f:
    pickle.dump(bundle, f)
print(f"\nModel bundle saved to: {MODEL_OUTPUT}")
print("\n=== TERMINE ===")
