import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


print("Loading PhiUSIIL dataset...")

data = pd.read_csv(
    "data/PhiUSIIL_Phishing_URL_Dataset.csv"
)

print("Dataset loaded!")
print(f"Total URLs: {len(data)}")


# ==================================================
# LABEL
# ==================================================
#
# 0 = Phishing
# 1 = Legitimate
#
y = 1 - data["label"]


# ==================================================
# ONLY LIVE-CALCULABLE FEATURES
# ==================================================
#
# These features can also be calculated directly
# from a URL entered by the user.
#
FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS"
]


print()
print("Selecting live-calculable URL features...")

X = data[FEATURES].copy()

X = X.fillna(0)


print(
    f"Features used: {len(FEATURES)}"
)

print()
print("Feature names:")
print(FEATURES)


# ==================================================
# TRAIN / TEST SPLIT
# ==================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print()
print(
    f"Training samples: {len(X_train)}"
)

print(
    f"Testing samples: {len(X_test)}"
)


# ==================================================
# RANDOM FOREST
# ==================================================

print()
print("Creating Random Forest model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
    max_depth=14,
    min_samples_leaf=2,
    max_features="sqrt"
)


# ==================================================
# TRAIN
# ==================================================

print("Training model...")

model.fit(
    X_train,
    y_train
)

print("Training completed!")


# ==================================================
# EVALUATION
# ==================================================

print()
print("Evaluating model...")

predictions = model.predict(
    X_test
)


accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    pos_label=0
)

recall = recall_score(
    y_test,
    predictions,
    pos_label=0
)

f1 = f1_score(
    y_test,
    predictions,
    pos_label=0
)


print()
print("========== MODEL PERFORMANCE ==========")

print(
    f"Accuracy : {accuracy * 100:.2f}%"
)

print(
    f"Precision: {precision * 100:.2f}%"
)

print(
    f"Recall   : {recall * 100:.2f}%"
)

print(
    f"F1 Score : {f1 * 100:.2f}%"
)

print(
    "======================================="
)


# ==================================================
# CONFUSION MATRIX
# ==================================================

cm = confusion_matrix(
    y_test,
    predictions,
    labels=[1, 0]
)

print()
print("========== CONFUSION MATRIX ==========")

print(
    "                  Predicted"
)

print(
    "              Legitimate  Phishing"
)

print(
    f"Actual Legitimate  {cm[0][0]:6d}  {cm[0][1]:8d}"
)

print(
    f"Actual Phishing    {cm[1][0]:6d}  {cm[1][1]:8d}"
)

print(
    "======================================="
)


# ==================================================
# CLASSIFICATION REPORT
# ==================================================

print()
print(
    "========== CLASSIFICATION REPORT =========="
)

print(
    classification_report(
        y_test,
        predictions,
        labels=[1, 0],
        target_names=[
            "Legitimate",
            "Phishing"
        ]
    )
)

print(
    "==========================================="
)


# ==================================================
# FEATURE IMPORTANCE
# ==================================================

print()
print(
    "========== FEATURE IMPORTANCE =========="
)

importance = sorted(
    zip(
        FEATURES,
        model.feature_importances_
    ),
    key=lambda x: x[1],
    reverse=True
)

for name, value in importance:

    print(
        f"{name:35s}: {value:.4f}"
    )

print(
    "========================================="
)


# ==================================================
# SAVE MODEL
# ==================================================

joblib.dump(
    model,
    "backend/phishing_model.pkl"
)

print()
print(
    "Model saved successfully!"
)

print(
    "File: backend/phishing_model.pkl"
)

print()
print(
    "Model expects:"
)

print(
    list(model.feature_names_in_)
)