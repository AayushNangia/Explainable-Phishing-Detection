# PhishGuard XAI — Explainable Phishing Detection and Advisory System

**Detect → Explain → Advise.** A full-stack system that classifies URLs and e-mails/messages as
`SAFE`, `SUSPICIOUS` or `PHISHING`, explains the decision with **SHAP**, **LIME** and explicit
**security rules**, and produces finding-specific security advice.

| Layer | Technology |
|---|---|
| Frontend | React 18 + Vite, Tailwind CSS 3, React Router, Axios, Recharts, Lucide |
| Backend | Python, FastAPI, Pydantic, PyMongo |
| ML / NLP | scikit-learn (Logistic Regression, Decision Tree, Random Forest), pandas, NumPy, NLTK (tokeniser + Porter stemmer), TF-IDF |
| Explainability | SHAP (Tree/Linear explainers), LIME (tabular + text) |
| Database | MongoDB (with a clearly-labelled local-file fallback) |

> **Security:** every URL is treated as untrusted text. The system performs **static analysis only** —
> it never opens, fetches, resolves (no DNS) or follows a submitted URL, so SSRF / redirect / command-injection
> paths do not exist. Only `http(s)` (or scheme-less) URLs are accepted; `javascript:`, `data:`, `file:` etc. are rejected.

---

## 1. Architecture

```
React (Vite, :5173) ──REST/JSON──► FastAPI (:8000)
                                     ├─ routes/        analyze · history · system
                                     ├─ services/hybrid.py   hybrid engine + advisory
                                     ├─ ml/            url_features · email_features · prediction · training scripts
                                     ├─ security/rules.py    explicit URL + e-mail rules (noisy-OR risk)
                                     ├─ explainability/      shap_explainer · lime_explainer
                                     └─ database/store.py    MongoDB  (or LOCAL FILE MODE fallback)
```

### Hybrid risk model
```
Final risk = α × ML risk + (1 − α) × Rule risk
ML risk   = calibrated probability (Platt/sigmoid, fitted on the validation set)
Rule risk = 1 − Π(1 − wᵢ)  over triggered rules  (noisy-OR; weights are documented expert heuristics)
SAFE  : risk < t_safe        SUSPICIOUS : t_safe ≤ risk < t_phish        PHISHING : risk ≥ t_phish
```
`α`, `t_safe`, `t_phish` are chosen **on the validation set only** (`ml/common.py::tune_hybrid`):
α maximises PR-AUC (constrained to α ≤ 0.9 so rules always keep ≥10 % weight — the unconstrained optimum is
stored and shown in the UI); `t_phish` maximises F1; `t_safe` is the largest threshold that lets ≤2 % of validation
phishing items fall below it. These are validation-optimal under stated criteria, **not** claims of global optimality.

### Data protocol (no leakage)
Stratified **65 % train / 15 % validation / 20 % test**. TF-IDF, χ² feature selection and scaling are fitted on the
training split only. Model selection (highest validation F2, recall-weighted), calibration and hybrid tuning use the
validation split. The test split is used once for the numbers shown in the UI.

---

## 2. Running on Windows

Prerequisites: **Python 3.10–3.12**, **Node.js 18+**, Git. MongoDB is optional (see §4).

### Backend
```bat
cd phishing-detection-system\backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy ..\.env.example ..\.env
uvicorn main:app --reload
```
API: http://localhost:8000 · Interactive docs: http://localhost:8000/docs

### Frontend (new terminal)
```bat
cd phishing-detection-system\frontend
npm install
npm run dev
```
App: http://localhost:5173  (the frontend reads `VITE_API_URL`, default `http://localhost:8000`).

### Pre-trained models
The ZIP ships `backend/models/*.joblib` and `*_metrics.json` produced by the training scripts below, so the app works
immediately. If those files are missing the UI shows **“DEMO MODE — MODEL NOT TRAINED”** and uses rules only; no
fake ML output is ever produced. Models are pinned to scikit-learn 1.5.2 — if you change versions, retrain.

---

## 3. Datasets and training

All data are real public sources; nothing is synthesised or randomly labelled. Provenance is written to
`backend/datasets/provenance.json`.

| Task | Class | Source |
|---|---|---|
| URL | phishing | **Phishing.Database** “ACTIVE” list — https://github.com/mitchellkrogza/Phishing.Database (aggregates PhishTank, OpenPhish and other feeds) |
| URL | legitimate | `good` URLs from https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs |
| Email | spam (positive) / ham | **Enron-Spam** (Metsis et al., 2006) via https://github.com/MWiechmann/enron_spam_data |

```bat
cd backend && venv\Scripts\activate
python -m ml.download_datasets --url --email     :: downloads (~100 MB) and builds datasets\urls.csv / emails.csv
python -m ml.train_url_model                     :: ~1 min
python -m ml.train_email_model                   :: ~1 min
```
Restart the API (or it loads models on startup) to use new models.

**Use PhishTank directly:** register at https://phishtank.org/developer_info.php, download `verified_online.csv`,
and build `datasets/urls.csv` with columns `url,label` (`1` = phishing, `0` = legitimate) then run
`python -m ml.train_url_model --dataset datasets\urls.csv`.

**Use a true phishing e-mail corpus (recommended for the e-mail model).** Download e.g. the Kaggle
“Phishing Email Dataset” (`Phishing_Email.csv`), CEAS-08, or Nazario, then:
```bat
python -m ml.download_datasets --email-csv path\to\Phishing_Email.csv --text-col "Email Text" --label-col "Email Type" --phishing-values "phishing email"
python -m ml.train_email_model
```
The training CSV schema is `subject,text,label` (label `1` = phishing).

---

## 4. MongoDB (optional)

1. Install MongoDB Community Server (https://www.mongodb.com/try/download/community) as a Windows service, or
   run `docker run -d -p 27017:27017 mongo:7`.
2. In `.env` keep `MONGODB_URI=mongodb://localhost:27017` (use an Atlas `mongodb+srv://…` URI if you prefer).
3. Restart the API. The top bar and Settings page show **“MongoDB (persistent)”**.

If MongoDB is unreachable (or `MONGODB_URI` is empty) the API falls back to **LOCAL FILE MODE**
(`backend/local_store/scans.json`). This is a development fallback and is labelled as such in the UI — it is never
presented as MongoDB. Collections: `scans` (scan_id, input_type, input_summary, classification, risk_score,
ml_probability, rule_findings, explanation_summary, advisory, created_at, result) and `model_metrics`
(model_name, dataset_name, accuracy, precision, recall, f1_score, roc_auc, evaluation_date).

### `.env`
| Variable | Default | Meaning |
|---|---|---|
| `FRONTEND_ORIGIN` | `http://localhost:5173` | CORS allow-list (comma-separated) |
| `MONGODB_URI` | `mongodb://localhost:27017` | empty ⇒ local file mode |
| `MONGODB_DB` | `phishing_detection` | database name |
| `STORE_FULL_INPUT` | `false` | if `true`, raw URLs / e-mail bodies are stored (shown in Settings) |
| `FORCE_LOCAL_STORAGE` | `false` | skip MongoDB even if reachable |

### Privacy
By default only the classification, score, findings, explanation and a **masked** input summary are stored. URL query
strings are replaced by `?[query hidden]`; e-mail bodies and highlighted text are not persisted; sender is reduced to its
domain. Passwords, OTPs and tokens are never stored.

---

## 5. API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/analyze/url` | `{url}` → full hybrid result |
| POST | `/api/analyze/email` | `{subject, body, sender?}` → full hybrid result |
| GET | `/api/history?classification=&input_type=` | list scans |
| GET / DELETE | `/api/history/{scan_id}` | view / delete one scan |
| DELETE | `/api/history` | clear all history |
| GET | `/api/dashboard/stats` | statistics computed from stored records |
| GET | `/api/models/performance` | metrics produced by the training scripts |
| GET | `/api/health`, `/api/settings` | status, storage mode, model status |

## 6. Tests

```bat
cd backend && venv\Scripts\activate && pytest          :: 31 backend tests
cd frontend && npm test                                   :: 5 integration tests (start the API first)
```
Backend tests cover URL feature extraction, input validation (SSRF-style schemes), e-mail preprocessing, rules,
risk aggregation, API validation, privacy of stored data, dashboard stats and DEMO MODE. Frontend tests render the real
pages against the running API.

## 7. Limitations (state these honestly in your viva)

* **Dataset bias.** Phishing and legitimate URLs come from *different collections* (and different periods), so models can partly
  learn collection artefacts; the reported test scores are **optimistic** relative to real traffic. Lexical features also cannot see
  page content, WHOIS age, TLS certificates or reputation feeds.
* **E-mail model is trained on Enron-Spam (spam vs. ham)**, not a curated phishing corpus. Its positive class is unsolicited / scam
  mail. Retrain with a phishing corpus (§3) for a phishing-specific model.
* **Rules add little ranking power on these corpora** (rules-only recall is low; validation-optimal α was 0.95 / 1.0, capped at 0.9
  by design). The rules mainly contribute transparency, interpretability, coverage of credential-phishing wording absent from the training data, and
  higher recall in the “flagged” (SUSPICIOUS+PHISHING) decision. Rule weights are hand-chosen heuristics.
* `has_https` is used by rules only because the training URLs were stored without a scheme.
* SHAP explains the model *before* calibration; LIME explains the calibrated probability and varies slightly between runs.
* Grammar/spelling is never treated as proof of phishing; no spell-checker feature is used.
* Automated classification is not a guarantee of safety.

## 8. Folder structure
```
phishing-detection-system/
├─ README.md · .env.example · .gitignore
├─ frontend/  (src/{components,pages,services,hooks,tests}, package.json, vite/tailwind config)
└─ backend/
   ├─ main.py · config.py · schemas.py · requirements.txt · pytest.ini
   ├─ routes/ (analyze, history, system)   services/hybrid.py
   ├─ ml/ (url_features, email_features, prediction, common, download_datasets, train_url_model, train_email_model)
   ├─ explainability/ (shap_explainer, lime_explainer)   security/rules.py   database/store.py
   ├─ models/ (*.joblib, *_metrics.json)   datasets/ (provenance.json, urls.csv)   tests/
```

## 9. Troubleshooting
* **“Cannot reach the backend API”** — start `uvicorn main:app --reload` in `backend/`, check port 8000 is free.
* **CORS error** — make `FRONTEND_ORIGIN` match the exact frontend URL (e.g. `http://127.0.0.1:5173` vs `localhost`).
* **`ModuleNotFoundError: ml`** — run commands from the `backend` folder (`python -m ml.train_url_model`).
* **Models fail to load / version warning** — `pip install -r requirements.txt` (pinned versions) or retrain.
* **MongoDB not used** — check the service is running; the UI label tells you which storage is active.
* **Port 5173 busy** — `npm run dev -- --port 5174` and add that origin to `FRONTEND_ORIGIN`.
* **Windows long-path / pip build errors** — use Python 3.11/3.12 (binary wheels exist for all pinned packages).
