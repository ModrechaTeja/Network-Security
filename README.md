# NetworkSecurity — Phishing URL Detection

An end-to-end ML system that classifies URLs as **phishing** or **legitimate**,
with a FastAPI dashboard supporting both single-URL and batch CSV prediction.

## Pipeline

```
MongoDB → Data Ingestion → Data Validation → Data Transformation
   → Model Training (5 algorithms, GridSearchCV) → Best Model
   → model.pkl + preprocessor.pkl → FastAPI App
```

## Features

- **Single URL check** (`POST /predict-url`) — paste a live URL, get an instant
  verdict. Features are computed live from URL parsing, DNS/WHOIS, and page
  content. A few legacy signals (Alexa Rank, Google's old PageRank API) no
  longer have a live data source — these are clearly flagged, not faked.
- **Batch CSV prediction** (`POST /predict`) — upload a CSV of pre-extracted
  features and score every row.
- **Retrain endpoint** (`GET /train`) — re-runs the full pipeline.

## Tech Stack

Python · scikit-learn · Pandas/NumPy · MongoDB · FastAPI · MLflow · DagsHub · BeautifulSoup · Requests · WHOIS · DNS · Docker

## Project Structure

```
networksecurity/
├── components/         # ingestion, validation, transformation, training
├── pipeline/            # training_pipeline.py
├── utils/ml_utils/
│   ├── model/            # NetworkModel wrapper
│   └── feature_extraction/  # url_feature_extractor.py
app.py                   # FastAPI app
main.py                  # standalone training run
templates/                # dashboard UI
final_model/              # trained model.pkl + preprocessor.pkl
```

## Run Locally

```bash
pip install -r requirements.txt
pip install -e .
python push_data.py   # one-time: load CSV into MongoDB
python main.py         # train model
python app.py           # start dashboard at http://127.0.0.1:8000
```

## Notes

- MLflow/DagsHub tracking is implemented and has been tested successfully, but is disabled by default to keep local execution lightweight and avoid unnecessary remote tracking overhead.
- AWS S3 synchronization code is included but disabled because cloud deployment is not currently configured.


## The dashboard will be available at:
http://127.0.0.1:8000