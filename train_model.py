import os
import glob
import re  # needed for TextStats
import email
import numpy as np  # numpy array ops
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import FunctionTransformer  # to convert sparse to dense
from sklearn.metrics import classification_report
from joblib import dump

# Named function to convert sparse matrices to dense

def to_dense(X):
    if hasattr(X, 'toarray'):
        return X.toarray()
    return X

# 1) Load email bodies from a directory
def load_emails(path, label):
    texts, labels = [], []
    for fp in glob.glob(os.path.join(path, '*')):
        try:
            with open(fp, errors='ignore') as f:
                msg = email.message_from_file(f)
            body = ''
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    disp = str(part.get('Content-Disposition'))
                    if ctype == 'text/plain' and 'attachment' not in disp:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors='ignore')
            texts.append(body)
            labels.append(label)
        except Exception:
            continue
    return texts, labels

# 2) Extra hand-coded features: URL count, exclamations, ALL-CAPS words, length
class TextStats(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        stats = []
        for doc in X:
            urls = len(re.findall(r'https?://', doc))
            excl = doc.count('!')
            caps = len(re.findall(r'\b[A-Z]{2,}\b', doc))
            length = len(doc)
            stats.append([urls, excl, caps, length])
        return np.array(stats)

# 3) Load ham/spam datasets
ham_texts, ham_labels = load_emails('data/easy_ham', 0)
spam_texts, spam_labels = load_emails('data/spam', 1)
X = ham_texts + spam_texts
y = ham_labels + spam_labels

# 4) Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 5) Build pipeline with named to_dense
pipeline = Pipeline([
    ('features', FeatureUnion([
        ('tfidf', TfidfVectorizer(
            stop_words='english', ngram_range=(1,2), max_df=0.85, min_df=5
        )),
        ('stats', TextStats())
    ])),
    # Convert sparse output to dense using named function
    ('to_dense', FunctionTransformer(to_dense, accept_sparse=True)),
    ('clf', HistGradientBoostingClassifier(
        max_iter=200, learning_rate=0.1, random_state=42
    ))
])

# 6) Hyperparameter grid
grid = GridSearchCV(
    pipeline,
    param_grid={
        'clf__learning_rate': [0.05, 0.1, 0.2],
        'clf__max_iter': [100, 200]
    },
    cv=5,
    n_jobs=-1,
    verbose=2,
    error_score='raise'
)

# 7) Fit
print("Starting grid search. This may take a few minutes...")
grid.fit(X_train, y_train)
print("Best params:", grid.best_params_)

# 8) Evaluate
y_pred = grid.predict(X_test)
print(classification_report(y_test, y_pred, target_names=['Ham','Spam']))

# 9) Save robust model
dump(grid.best_estimator_, 'scam_detector_robust.joblib')
print("Training complete — model saved to scam_detector_robust.joblib")
