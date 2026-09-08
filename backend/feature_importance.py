import joblib
import pandas as pd
import matplotlib.pyplot as plt

# Load trained model
model = joblib.load("backend/phishing_model.pkl")

# Feature names used by our model
feature_names = [
    "url_length",
    "hostname_length",
    "path_length",
    "has_https",
    "has_ip",
    "num_dots",
    "num_hyphens",
    "num_subdomains",
    "has_at_symbol",
    "num_digits",
    "num_special_chars",
    "has_suspicious_words"
]

# Get feature importance
importance = model.feature_importances_

# Create dataframe
importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importance
})

# Sort by importance
importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)

# Print results
print()
print("========== FEATURE IMPORTANCE ==========")

for _, row in importance_df.iterrows():
    print(
        f"{row['Feature']:25s} : "
        f"{row['Importance']:.4f}"
    )

print("========================================")


# Create chart
plt.figure(figsize=(10, 6))

plt.barh(
    importance_df["Feature"],
    importance_df["Importance"]
)

plt.xlabel("Importance")
plt.ylabel("Feature")
plt.title("PhishGuard AI - Feature Importance")

plt.gca().invert_yaxis()

plt.tight_layout()

plt.savefig(
    "backend/feature_importance.png",
    dpi=300
)

plt.show()

print()
print("Feature importance chart saved!")
print("File: backend/feature_importance.png")