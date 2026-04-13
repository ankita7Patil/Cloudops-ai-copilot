#!/bin/bash
# infra/setup.sh — run once after creating GCP project

PROJECT_ID="uaci-mvp"
REGION="us-central1"

# Enable all required APIs
gcloud services enable \
  run.googleapis.com \
  cloudfunctions.googleapis.com \
  bigquery.googleapis.com \
  firestore.googleapis.com \
  pubsub.googleapis.com \
  storage.googleapis.com \
  firebase.googleapis.com \
  aiplatform.googleapis.com \
  secretmanager.googleapis.com \
  cloudscheduler.googleapis.com \
  logging.googleapis.com \
  --project=$PROJECT_ID

# Create BigQuery dataset
bq mk --dataset --location=US ${PROJECT_ID}:uaci_data

# Create Pub/Sub topics
gcloud pubsub topics create raw-security-events --project=$PROJECT_ID
gcloud pubsub topics create raw-billing-events --project=$PROJECT_ID
gcloud pubsub topics create incident-alerts --project=$PROJECT_ID
gcloud pubsub topics create action-commands --project=$PROJECT_ID

# Create Cloud Storage bucket
gsutil mb -l $REGION gs://${PROJECT_ID}-artifacts

# Store Gemini API key in Secret Manager
echo -n "YOUR_GEMINI_API_KEY" | gcloud secrets create GEMINI_API_KEY \
  --data-file=- --project=$PROJECT_ID

# Create Firestore database (native mode)
gcloud firestore databases create --location=$REGION --project=$PROJECT_ID

# Deploy backend to Cloud Run
gcloud run deploy uaci-backend \
  --source ./backend \
  --region $REGION \
  --allow-unauthenticated \
  --set-env-vars GCP_PROJECT_ID=$PROJECT_ID \
  --set-secrets GEMINI_API_KEY=GEMINI_API_KEY:latest \
  --project=$PROJECT_ID

echo "Setup complete. Now run: cd data-gen && python generate_all.py"
