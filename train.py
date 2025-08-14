import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib

# 1. قراءة البيانات
data_path = "data/dataset_phishing.csv"
df = pd.read_csv(data_path)

# 2. الميزات التي استخدمتها (تأكد أن كلها موجودة في الـ dataset)
features = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at',
    'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde',
    'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn',
    'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path',
    'https_token', 'ratio_digits_url', 'ratio_digits_host', 'punycode',
    'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
    'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service',
    'path_extension', 'nb_redirection', 'nb_external_redirection'
]

X = df[features]

# 3. المتغير الهدف (phishing أو legitimate)
le = LabelEncoder()
y = le.fit_transform(df['status'])  # phishing=1 أو legitimate=0

# 4. تقسيم البيانات
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. تدريب النموذج
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# 6. تقييم النموذج
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred, target_names=le.classes_))

# 7. حفظ النموذج والـ LabelEncoder
joblib.dump(model, 'model.pkl')
joblib.dump(le, 'label_encoder.pkl')
