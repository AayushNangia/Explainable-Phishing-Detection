"""Email / message preprocessing and linguistic feature extraction.

Pipeline (all fitted ONLY on training data when trained via train_email_model.py):

    raw text ─┬─► clean_text ► TF-IDF (1-2 grams) ─┐
              └─► linguistic indicators (log1p) ───┴► SelectKBest(chi2) ► classifier

Everything here is plain-Python / sklearn so it pickles cleanly and can be re-used by LIME
(which perturbs raw text and needs a text → probability function).
"""
from __future__ import annotations

import html
import re

import numpy as np
from nltk.stem import PorterStemmer
from nltk.tokenize import RegexpTokenizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer

from security.rules import LEXICON, URL_RE, lexicon_counts

# A compact English stop-word list embedded here so no NLTK corpus download is needed.
STOPWORDS = frozenset("""a about above after again against all am an and any are as at be because been before being below
between both but by can did do does doing down during each few for from further had has have having he her here hers
herself him himself his how i if in into is it its itself just me more most my myself no nor not now of off on once only
or other our ours ourselves out over own same she should so some such than that the their theirs them themselves then
there these they this those through to too under until up very was we were what when where which while who whom why will
with you your yours yourself yourselves would could also may might shall us""".split())

_TOKENIZER = RegexpTokenizer(r"[a-z][a-z']+|urltoken|emailtoken")
_STEM = PorterStemmer()
_TAG_RE = re.compile(r"<[^>]+>")
_EMAIL_RE = re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+")
_NUM_RE = re.compile(r"\d+")

INDICATOR_NAMES = [
    "urgency_terms", "threat_terms", "credential_terms", "financial_terms", "reward_terms",
    "generic_greeting", "call_to_action", "num_urls", "has_ip_url", "exclamation_count",
    "uppercase_ratio", "has_html",
]


def clean_text(text: str) -> str:
    """HTML-strip, normalise URLs/e-mails/numbers, lower-case, tokenise, drop stop-words, stem."""
    if not isinstance(text, str):
        return ""
    t = html.unescape(text)
    t = _TAG_RE.sub(" ", t)
    t = URL_RE.sub(" urltoken ", t)
    t = _EMAIL_RE.sub(" emailtoken ", t)
    t = _NUM_RE.sub(" ", t.lower())
    tokens = _TOKENIZER.tokenize(t)
    return " ".join(_STEM.stem(w) for w in tokens if w not in STOPWORDS and len(w) > 1)


def indicator_vector(text: str) -> list[float]:
    """Linguistic / security indicators (counts and ratios)."""
    text = text if isinstance(text, str) else ""
    c = lexicon_counts(text)
    letters = [ch for ch in text if ch.isalpha()]
    urls = URL_RE.findall(text)
    return [
        c["urgency"], c["threat"], c["credential"], c["financial"], c["reward"],
        c["generic_greeting"], c["click_bait"], len(urls),
        int(any(re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", u) for u in urls)),
        text.count("!"), sum(ch.isupper() for ch in letters) / max(len(letters), 1),
        int(bool(_TAG_RE.search(text))),
    ]


def _clean_many(texts):
    return [clean_text(t) for t in texts]


def _indicators_many(texts):
    # log1p keeps the values non-negative (needed by chi2) and tames large counts
    return np.log1p(np.array([indicator_vector(t) for t in texts], dtype=float))


def build_preprocessor(max_features: int = 6000, k_best: int = 2000) -> Pipeline:
    """Un-fitted preprocessing pipeline: text → selected feature matrix."""
    union = FeatureUnion([
        ("tfidf", Pipeline([
            ("clean", FunctionTransformer(_clean_many, validate=False)),
            ("vec", TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_df=0.9, max_features=max_features, sublinear_tf=True)),
        ])),
        ("ind", FunctionTransformer(_indicators_many, validate=False)),
    ])
    return Pipeline([("features", union), ("select", SelectKBest(chi2, k=k_best))])


def selected_feature_names(prep: Pipeline) -> list[str]:
    union = prep.named_steps["features"]
    vocab = union.transformer_list[0][1].named_steps["vec"].get_feature_names_out().tolist()
    names = [f"word: {v}" for v in vocab] + [f"indicator: {n}" for n in INDICATOR_NAMES]
    mask = prep.named_steps["select"].get_support()
    return [n for n, m in zip(names, mask) if m]


def compose_message(subject: str, body: str) -> str:
    subject = (subject or "").strip()
    body = (body or "").strip()
    return f"{subject}\n{body}".strip()
