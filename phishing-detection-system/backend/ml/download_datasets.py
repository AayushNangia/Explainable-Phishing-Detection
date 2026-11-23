"""Download and prepare REAL public datasets. Nothing is synthesised or randomly labelled.

Usage (from the backend folder):
    python -m ml.download_datasets --url --email
    python -m ml.download_datasets --url --max-per-class 40000

URL data
    phishing   : Phishing.Database "ACTIVE" list (aggregates PhishTank, OpenPhish and other feeds)
                 https://github.com/mitchellkrogza/Phishing.Database
    legitimate : 'good' URLs from faizann24/Using-machine-learning-to-detect-malicious-URLs
                 https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs
Email data
    Enron-Spam (Metsis, Androutsopoulos & Paliouras, 2006), spam vs ham, mirrored at
                 https://github.com/MWiechmann/enron_spam_data
    NOTE: Enron-Spam is a SPAM/HAM corpus (its spam class includes many scam / credential-lure
          messages) and not a curated phishing corpus. For a phishing-specific corpus use
          --email-csv with Nazario / CEAS-08 / Kaggle "Phishing_Email.csv" (see README).
"""
from __future__ import annotations

import argparse
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

from config import settings
from ml.url_features import URLValidationError, normalize_url

RAW = settings.datasets_dir / "raw"
PHISH_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
LEGIT_URL = "https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv"
ENRON_URL = "https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.zip"


def _get(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  using cached {dest.name}")
        return dest
    print(f"  downloading {url}")
    with requests.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(1 << 20):
                fh.write(chunk)
    return dest


def _bare(u: str) -> str:
    u = u.strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    return u.rstrip("/").lower()


def build_url_dataset(max_per_class: int = 40000, seed: int = 42) -> Path:
    print("Building URL dataset ...")
    ph = _get(PHISH_URL, RAW / "phishing_database_active.txt")
    lg = _get(LEGIT_URL, RAW / "legit_good_urls.csv")

    phish = pd.Series(ph.read_text(encoding="utf-8", errors="ignore").splitlines(), name="url")
    phish = phish[phish.str.match(r"^https?://", na=False)]
    legit = pd.read_csv(lg, on_bad_lines="skip")
    legit = legit[legit["label"] == "good"]["url"].astype(str)

    def prep(s: pd.Series, label: int) -> pd.DataFrame:
        df = pd.DataFrame({"url": s.map(_bare)})
        df = df[(df.url.str.len() > 3) & (df.url.str.len() <= 2000)]
        df = df.drop_duplicates("url")
        ok = []
        for u in df.url:                      # keep only URLs our validator can parse safely
            try:
                normalize_url(u)
                ok.append(True)
            except URLValidationError:
                ok.append(False)
        df = df[ok]
        df["label"] = label
        return df

    p, l = prep(phish, 1), prep(legit, 0)
    overlap = set(p.url) & set(l.url)         # drop anything claimed by both classes
    p, l = p[~p.url.isin(overlap)], l[~l.url.isin(overlap)]
    counts_before = {"phishing_unique": len(p), "legitimate_unique": len(l), "label_conflicts_removed": len(overlap)}
    p = p.sample(min(max_per_class, len(p)), random_state=seed)
    l = l.sample(min(max_per_class, len(l)), random_state=seed)
    df = pd.concat([p, l]).sample(frac=1, random_state=seed).reset_index(drop=True)
    out = settings.datasets_dir / "urls.csv"
    df.to_csv(out, index=False)
    _write_provenance("urls", {
        "file": out.name, "rows": len(df), "phishing": int(df.label.sum()), "legitimate": int((df.label == 0).sum()),
        "phishing_source": PHISH_URL, "legitimate_source": LEGIT_URL, "scheme_removed_from_all_urls": True,
        "sampling": f"random sample up to {max_per_class} per class (seed {seed})", **counts_before,
        "limitation": ("Legitimate and phishing URLs come from different collections. Models can partly learn "
                       "collection-specific artefacts, so test metrics are optimistic compared with real-world traffic."),
    })
    print(f"  wrote {out} ({len(df)} rows)")
    return out


def build_email_dataset(max_rows: int = 30000, seed: int = 42, csv_path: str | None = None,
                        text_col: str | None = None, label_col: str | None = None,
                        phishing_values: str | None = None) -> Path:
    print("Building email dataset ...")
    out = settings.datasets_dir / "emails.csv"
    if csv_path:
        df = pd.read_csv(csv_path)
        text_col = text_col or next((c for c in df.columns if c.lower() in ("email text", "text", "body", "message", "text_combined")), None)
        label_col = label_col or next((c for c in df.columns if c.lower() in ("email type", "label", "class", "type")), None)
        if not text_col or not label_col:
            raise SystemExit(f"Could not detect columns in {csv_path}. Pass --text-col and --label-col. Columns: {list(df.columns)}")
        pos = {v.strip().lower() for v in (phishing_values or "phishing email,phishing,spam,1,malicious").split(",")}
        y = df[label_col].astype(str).str.strip().str.lower().isin(pos).astype(int)
        res = pd.DataFrame({"subject": "", "text": df[text_col].astype(str), "label": y})
        source = f"user supplied: {csv_path}"
        positive = f"values {sorted(pos)} in column '{label_col}'"
    else:
        z = _get(ENRON_URL, RAW / "enron_spam_data.zip")
        with zipfile.ZipFile(z) as zf:
            name = next(n for n in zf.namelist() if n.endswith(".csv"))
            df = pd.read_csv(io.BytesIO(zf.read(name)))
        cols = {c.lower().replace(" ", "_"): c for c in df.columns}
        res = pd.DataFrame({
            "subject": df[cols["subject"]].fillna("").astype(str),
            "text": df[cols["message"]].fillna("").astype(str),
            "label": (df[cols["spam/ham"]].astype(str).str.lower() == "spam").astype(int),
        })
        source = ENRON_URL
        positive = "'spam' class of Enron-Spam (spam / unsolicited scam-style mail, NOT curated phishing)"
    res["text"] = res["text"].str.slice(0, 5000)
    res = res[(res.text.str.strip().str.len() > 20)]
    res = res.assign(_k=(res.subject + "|" + res.text).str.lower().str.replace(r"\s+", " ", regex=True))
    n_before = len(res)
    res = res.drop_duplicates("_k").drop(columns="_k")
    dups = n_before - len(res)
    if len(res) > max_rows:   # stratified down-sample for CPU-friendly training
        res = res.groupby("label", group_keys=False).apply(lambda g: g.sample(int(max_rows * len(g) / len(res)), random_state=seed))
    res = res.sample(frac=1, random_state=seed).reset_index(drop=True)
    res.to_csv(out, index=False)
    _write_provenance("emails", {
        "file": out.name, "rows": len(res), "positive_class": int(res.label.sum()), "negative_class": int((res.label == 0).sum()),
        "source": source, "positive_label_meaning": positive, "duplicates_removed": int(dups),
        "limitation": ("Enron-Spam is a spam/ham corpus. The positive class is spam/scam mail, not strictly phishing. "
                       "Train on a phishing corpus (Nazario/CEAS-08) for a phishing-specific model.") if not csv_path else "User supplied dataset.",
    })
    print(f"  wrote {out} ({len(res)} rows)")
    return out


def _write_provenance(key: str, info: dict) -> None:
    path = settings.datasets_dir / "provenance.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    info["prepared_at"] = datetime.now(timezone.utc).isoformat()
    data[key] = info
    path.write_text(json.dumps(data, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", action="store_true", help="download + build URL dataset")
    ap.add_argument("--email", action="store_true", help="download + build email dataset (Enron-Spam)")
    ap.add_argument("--max-per-class", type=int, default=40000)
    ap.add_argument("--max-email-rows", type=int, default=30000)
    ap.add_argument("--email-csv", help="use your own email CSV (e.g. Phishing_Email.csv, CEAS_08.csv)")
    ap.add_argument("--text-col"); ap.add_argument("--label-col"); ap.add_argument("--phishing-values")
    a = ap.parse_args()
    if not (a.url or a.email or a.email_csv):
        ap.error("choose --url and/or --email")
    if a.url:
        build_url_dataset(a.max_per_class)
    if a.email or a.email_csv:
        build_email_dataset(a.max_email_rows, csv_path=a.email_csv, text_col=a.text_col, label_col=a.label_col,
                            phishing_values=a.phishing_values)
