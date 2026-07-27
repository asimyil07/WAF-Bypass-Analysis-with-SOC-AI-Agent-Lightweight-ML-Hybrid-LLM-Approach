import os
import numpy as np
import joblib
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import normalize
from sklearn.neighbors import NearestNeighbors

MODEL_NAME = r"./models/minilm"
TRAIN_FILE = r"./data/baseline_traffic.txt"
K = 5

USE_GPU = False

if USE_GPU:
    os.environ["CUDA_VISIBLE_DEVICES"] = "0"
else:
    os.environ["CUDA_VISIBLE_DEVICES"] = ""

def load_requests(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    raw = raw.replace("\r", "\n")
    blocks = raw.split("\n\n")

    requests = []
    for b in blocks:
        b = b.strip()
        if len(b) < 10:
            continue
        requests.append(" ".join(b.splitlines()))

    return requests

def embed(model, texts):
    return model.encode(
        texts,
        batch_size=32,
        show_progress_bar=True,
        convert_to_numpy=True
    )

print("[+] Loading training data...")
requests = load_requests(TRAIN_FILE)
print(f"[+] Requests loaded: {len(requests)}")

print("[+] Loading embedding model...")
model = SentenceTransformer(MODEL_NAME)

print("[+] Embedding requests...")
X = embed(model, requests)
X = normalize(X, norm="l2")

print("[+] Training k-NN...")
knn = NearestNeighbors(n_neighbors=K, metric="cosine")
knn.fit(X)

print("[+] Saving artifacts...")
joblib.dump(knn, "knn_model2.pkl")
np.save("train_embeddings2.npy", X)
joblib.dump({"mode": "request-level"}, "config2.pkl")

print("[✔] Training completed (request-level model)")
