import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

# This class is now in its own file to be safely imported
class TextStats(BaseEstimator, TransformerMixin):
    """Extract URL count, exclamations, ALL-CAPS words, and length from text."""
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        stats = []
        for doc in X:
            urls   = len(re.findall(r'https?://', doc))
            excl   = doc.count('!')
            caps   = len(re.findall(r'\b[A-Z]{2,}\b', doc))
            length = len(doc)
            stats.append([urls, excl, caps, length])
        return np.array(stats)

# We can move this helper here too for consistency
def to_dense(X):
    if hasattr(X, 'toarray'):
        return X.toarray()
    return X