import re
import pandas as pd
import os
import math
from statistics import mean, stdev
from collections import Counter
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC, LinearSVC
from sklearn.metrics import classification_report, confusion_matrix

# === Configuration ===
# Update file paths as needed
LEGIT_FILE     = r"C:\\Users\\kyrai\\Desktop\\fast-flux_dataset\\Alexa_168.95.1.1_benign.txt"
SUSPICIOUS_FILE= r"C:\\Users\\kyrai\\Desktop\\fast-flux_dataset\\BOT_168.95.1.1_benign.txt"
FASTFLUX_FILE  = r"C:\\Users\\kyrai\\Desktop\\fast-flux_dataset\\FluXOR_168.95.1_Attack.txt"

LABEL_FILES = [
    (LEGIT_FILE, 0),       # 0 = legitimate
    (SUSPICIOUS_FILE, 1),  # 1 = suspicious
    (FASTFLUX_FILE, 2)     # 2 = fast flux
]

# === Helper functions ===
def shannon_entropy(items):
    counts = Counter(items)
    total = sum(counts.values())
    entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
    return entropy

# === Feature extraction ===
def extract_features(dig_text: str) -> dict:
    # A records and TTLs
    a_records = re.findall(r'IN\s+A\s+(\d+\.\d+\.\d+\.\d+)', dig_text)
    ttl_vals = list(map(int, re.findall(r'(\d+)\s+IN\s+A\s+\d+\.\d+\.\d+\.\d+', dig_text)))
    # CNAME records
    cname_records = re.findall(r'IN\s+CNAME\s+(\S+)', dig_text)
    # NS records
    ns_records = re.findall(r'IN\s+NS\s+(\S+)', dig_text)
    # Additional A records
    additional_section = re.search(r'ADDITIONAL SECTION:(.*)', dig_text, re.DOTALL)
    additional_records = re.findall(r'IN\s+A\s+(\d+\.\d+\.\d+\.\d+)', additional_section.group(1)) if additional_section else []

    # Subnet diversity (/24)
    subnets = { '.'.join(ip.split('.')[:3]) for ip in a_records }

    # Compile feature dict
    feats = {
        'num_A_records': len(a_records),
        'ttl_min': min(ttl_vals) if ttl_vals else 0,
        'ttl_max': max(ttl_vals) if ttl_vals else 0,
        'ttl_avg': mean(ttl_vals) if ttl_vals else 0,
        'ttl_stddev': stdev(ttl_vals) if len(ttl_vals) > 1 else 0,
        'num_CNAME_records': len(cname_records),
        'num_NS_records': len(ns_records),
        'num_additional_records': len(additional_records),
        'ip_entropy': shannon_entropy(a_records) if a_records else 0,
        'num_unique_subnets': len(subnets)
    }
    return feats

# === Load and parse logs ===
records = []
for filepath, label_val in LABEL_FILES:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    content = open(filepath, 'r', encoding='utf-8').read()
    entries = re.split(r'(?=; <<>> DiG)', content)
    for entry in entries:
        text = entry.strip()
        if not text:
            continue
        feats = extract_features(text)
        feats['label'] = label_val
        records.append(feats)

# Create DataFrame
df = pd.DataFrame(records)
print(f"Loaded {len(df)} samples.")
print(df.head())

# === Prepare data ===
X = df.drop('label', axis=1)
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)

# === Classifiers ===
classifiers = {
    'DecisionTree': DecisionTreeClassifier(random_state=42),
    'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
    'GradientBoosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
    'LinearSVM': LinearSVC(max_iter=5000, class_weight='balanced', random_state=42)
}

# Optional: Uncomment to enable RBF SVM
# classifiers['SVM_RBF'] = SVC(kernel='rbf', class_weight='balanced', tol=1e-2, max_iter=1000)

# === Training & Evaluation ===
for name, clf in classifiers.items():
    print(f"\n=== Training {name} ===")
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(f"--- {name} Classification Report ---")
    print(classification_report(y_test, y_pred, zero_division=0))
    print(f"--- {name} Confusion Matrix ---")
    print(confusion_matrix(y_test, y_pred))

# === Hyperparameter tuning (example) ===
# param_grid = {'n_estimators': [50, 100, 200], 'max_depth': [None, 10, 20]}
# grid = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5, scoring='f1_macro')
# grid.fit(X_train, y_train)
# print("Best RF Params:", grid.best_params_)
# best_rf = grid.best_estimator_
# y_pred_rf = best_rf.predict(X_test)
# print("Grid RF Report:\n", classification_report(y_test, y_pred_rf, zero_division=0))
