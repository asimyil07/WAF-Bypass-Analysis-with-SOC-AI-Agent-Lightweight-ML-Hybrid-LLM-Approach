# WAF Bypass Analysis with SOC AI Agent: # 

Lightweight ML & Hybrid LLM ApproachIn AI projects, achieving minimum cost and maximum success is possible through models specifically trained for the target context.  

Based on this approach, we are sharing our project experiences developed alongside Burcu YARAR regarding the detection of web traffic that bypasses security systems. We hope it proves useful!  

WAF bypass alarms on SIEM systems often create significant False/Positive noise and alert fatigue. While sending all web traffic directly to an LLM is cost-prohibitive, leaving detection until after an application compromise poses a severe risk.  

We solved this challenge using a small, specialized Machine Learning model combined with a hybrid LLM architecture.  

⚠️ Note: This is not a 100% LLM-based SOC agent, but a hybrid anomaly detection system.  

🛠️ Architecture & WorkflowML Model: all-MiniLM-L6-v2 (22.7M Parameters, 384-dim Vector) + k-NN (Cosine Distance)  Pipeline: Normalized HTTP requests are vectorised and scored using a baseline k-NN index.  

🚦 Decision MechanismScore > 0.2 (Anomaly): Direct Firewall Block.  0.1 < Score ≤ 0.2 (Gray Area): Cost-effective LLM Analysis for granular inspection.  Score < 0.1 (Normal): Automatic Alert Closure via AbuseIPDB / VirusTotal checks.  

📊 First 24-Hour Results (Single Web Application)3,000+ "allowed" suspicious requests identified via k-NN.  30 IPs were caught carrying malicious payloads despite receiving an ALLOW action from the WAF.  26 IPs were blocked directly via the k-NN anomaly score, while 4 IPs in the gray area were blocked after LLM evaluation.  

Summary: The fast, lightweight ML model handles the heavy lifting, reserving the LLM strictly for complex cases in the gray zone.  Result: Zero analyst intervention required and minimal AI/GPU operational costs.  

🛠️ Detailed Component Breakdown

1. Model Training (train_knn.py)Purpose: 
Builds the baseline representation of "normal" web traffic using the all-MiniLM-L6-v2 Sentence Transformer model.

How it works:Reads a collection of baseline, unmalicious HTTP requests (baseline_traffic.txt).Generates 384-dimensional embeddings for each request.Fits a $k$-Nearest Neighbors ($k$-NN) model using Cosine Distance and exports the fitted artifacts (knn_model2.pkl, train_embeddings2.npy).

2. Live Inference API Server (detection_api.py)Purpose: Runs a lightweight FastAPI server that holds the $k$-NN model and embedding weights in memory for fast scoring.How it works:Calculates a dynamic dynamic anomaly threshold based on the 99th percentile of baseline distances.Accepts batches of HTTP payloads via a /predict HTTP POST endpoint.Measures cosine distance from the pre-trained space to output an anomaly score.

3. Log Ingestion & Processing (fetch_and_normalize.py & process_offenses.py)Purpose: Interfaces directly with QRadar SIEM to retrieve raw events and prepare payloads.How it works:Queries QRadar using AQL (Ariel Query Language) for unblocked (ALLOW) WAF logs.Strips out dynamic parameters (UUIDs, IPv4/v6 addresses, hex values, and numeric sequences) to retain attack semantics without overfitting to static strings.Sends normalized HTTP payloads directly to the FastAPI server for real-time scoring.

4. Threat Intelligence Checks (vt_check.py & abuse_check.py)Purpose: Verifies whether benign-looking traffic originates from known malicious infrastructure.How it works:Queries VirusTotal (v3 API) and AbuseIPDB in rate-limited batches.Filters out high-confidence malicious IPs before final decision-making.

5. Hybrid LLM Deep Dive (filter_llm_data.py & llm_analysis.py)Purpose: Handles the "Gray Area" ($0.1 < \text{Score} \le 0.2$).How it works:Requests that fall into the ambiguous range are extracted into LLMdata.txt.Passes payloads to an LLM (qwen/qwen3-next-80b-a3b-instruct or similar) via an asynchronous client with forced JSON formatting.Returns structured threat categorization, confidence, and severity scores.
  
6. Automated Remediation (close_offenses.py)Purpose: Closes false-positive SIEM offenses automatically to reduce SOC alert fatigue.How it works:Checks if an offense meets all false-positive conditions:VirusTotal score $= 0$AbuseIPDB score $< 50$k-NN Anomaly score $< 0.2$Calls QRadar’s REST API to close the target offense with reason code 1 (False Positive).

🚀 Step-by-Step Execution Guide
Prerequisites
Install the required Python dependencies:

Bash
pip install fastapi uvicorn sentence-transformers scikit-learn numpy joblib requests httpx openai tqdm urllib3
Execution Steps
Train the Baseline k-NN Model
Ensure you have a file containing clean baseline traffic, then run:

Bash
python train_knn.py
Start the FastAPI Model Server
Keep this running in the background to serve inference requests:

Bash
python detection_api.py
Fetch & Score SIEM Logs
Fetch open offenses from QRadar, normalize payloads, and send them to the API:

Bash
python process_offenses.py
Run Threat Intelligence Lookups
Check suspect IP addresses against VirusTotal and AbuseIPDB:

Bash
python vt_check.py
python abuse_check.py
Analyze Gray-Area Traffic via LLM
Filter ambiguous requests and perform structured LLM evaluation:

Bash
python filter_llm_data.py
python llm_analysis.py
Auto-Close False Positive Offenses
Close verified non-malicious alerts directly in QRadar:

Bash
python close_offenses.py
