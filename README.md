# Network Security - Phishing URL Classification

An end-to-end machine learning and MLOps project for classifying URLs as
**phishing or legitimate** using extracted URL-based features.

The project implements a modular machine learning pipeline covering data
ingestion, data validation, data transformation, model training, evaluation,
and batch prediction through a FastAPI web application.

---

## Project Overview

The system takes a dataset containing extracted URL features, trains multiple
classification models, performs hyperparameter tuning, and selects the
best-performing model for prediction.

The trained model is integrated with a FastAPI application that allows users
to upload a CSV file and obtain predictions for multiple URL records.

## Technologies Used

- **Python** - Core programming language
- **Scikit-learn** - Machine learning models, preprocessing, and GridSearchCV
- **Pandas & NumPy** - Data processing and numerical operations
- **MongoDB** - Data storage and data ingestion
- **FastAPI** - Prediction API and web application
- **MLflow & DagsHub** - Experiment tracking
- **Docker** - Containerization
- **HTML, CSS & JavaScript** - Custom web dashboard
- **Git & GitHub** - Version control

### ML Pipeline

```text
MongoDB
   ↓
Data Ingestion
   ↓
Data Validation
   ↓
Data Transformation
   ↓
Model Training & Hyperparameter Tuning
   ↓
Model Evaluation
   ↓
Best Model
   ↓
FastAPI Batch Prediction