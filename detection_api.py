import os
import sys
import json
import joblib
import torch
import numpy as np
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import normalize

MODEL_NAME = r"./models/all-MiniLM-L6-v2"
THRESHOLD_PERCENTILE = 99

KNN_MODEL = None
X_TRAIN = None
CONFIG = None
MODEL = None
THRESHOLD = None

class PayloadItem(BaseModel):
    ip: str
    normalized_payload: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    global KNN_MODEL, X_TRAIN, CONFIG, MODEL, THRESHOLD
    
    print("[+] Loading artifacts...")
    KNN_MODEL = joblib.load("knn_model.pkl")
    X_TRAIN = np.load("train_embeddings.npy")
    CONFIG = joblib.load("config.pkl")

    print("[+] Loading embedding model...")
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    print(f"[+] Using device: {device}")
    MODEL = SentenceTransformer(MODEL_NAME, device=device)

    print("[+] Calculating threshold...")
    n_neighbors_safe = min(5, len(X_TRAIN))
    train_distances, _ = KNN_MODEL.kneighbors(X_TRAIN, n_neighbors=n_neighbors_safe)
    train_scores = train_distances.mean(axis=1)
    
    THRESHOLD = np.percentile(train_scores, THRESHOLD_PERCENTILE)
    print(f"[+] Threshold set in memory: {THRESHOLD:.4f}")
    print("[+] Detection API server ready for requests!")

    yield

    print("[*] Shutting down detection service...")

app = FastAPI(title="Detection Model Server", lifespan=lifespan)

@app.post("/predict")
async def run_detection(payloads: List[PayloadItem]):
    if MODEL is None or KNN_MODEL is None:
        raise HTTPException(status_code=500, detail="Model/Artifacts not loaded in memory.")

    if not payloads:
        return {"status": "success", "logs": []}

    requests_for_model = [item.normalized_payload for item in payloads]

    X_test = MODEL.encode(
        requests_for_model,
        batch_size=32,
        show_progress_bar=False,
        convert_to_numpy=True
    )

    X_test = normalize(X_test, norm="l2")

    distances, _ = KNN_MODEL.kneighbors(X_test)
    scores = distances.mean(axis=1)

    formatted_output = []
    for score, item in zip(scores, payloads):
        label = "ANOMALY" if score > THRESHOLD else "NORMAL"
        ip_addr = item.ip
        payload_text = item.normalized_payload

        log_entry = (
            f"[{ip_addr}] [{label}] score={score:.4f}\n"
            f"{payload_text[:1200]}\n"
            f"{'-' * 80}\n"
        )
        formatted_output.append(log_entry)

    return {"status": "success", "logs": formatted_output}

if __name__ == "__main__":
    uvicorn.run("detection_api:app", host="0.0.0.0", port=8000, reload=False)
