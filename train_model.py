# train_model.py
import os, glob, email
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from joblib import dump

def load_emails(path, label):
    texts = []
    for filepath in glob.glob(os.path.join(path, '*')):
        with open(filepath, errors='ignore') as f:
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
    return texts, [label]*len(texts)

# load ham and spam
ham_texts, ham_labels = load_emails('data/easy_ham', 0)
spam_texts, spam_labels = load_emails('data/spam', 1)

X = ham_texts + spam_texts
y = ham_labels + spam_labels

# build & train pipeline
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(stop_words='english', max_df=0.7)),
    ('clf', LogisticRegression(max_iter=1000))
])
pipeline.fit(X, y)

# save model
dump(pipeline, 'scam_detector.joblib')
print("Training complete, model saved to scam_detector.joblib")
