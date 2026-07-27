import os
import json
import asyncio
import httpx
from openai import AsyncOpenAI
from tqdm.asyncio import tqdm

PROXY_URL = "http://USERNAME:PASSWORD@PROXY_IP:PORT"
API_KEY = os.getenv("LLM_API_KEY", "YOUR_API_KEY")

MODEL = "qwen/qwen3-next-80b-a3b-instruct"
INPUT_FILE = "LLMdata.txt"
OUTPUT_FILE = "analysis_results.json"

CONCURRENCY_LIMIT = 8 

http_client = httpx.AsyncClient(
    proxy=PROXY_URL,
    verify=False,
    timeout=httpx.Timeout(60.0, connect=10.0),
    transport=httpx.AsyncHTTPTransport(retries=3)
)

client = AsyncOpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=API_KEY,
    http_client=http_client
)

SYSTEM_PROMPT = """You are a WAF analyst. Determine if an HTTP request is malicious.
Return ONLY valid raw JSON with no markdown block formatting.

Format:
{"attack": true/false, "confidence": 0-100, "category": "...", "severity": "High/Medium/Low/None", "reason": "..."}"""

async def analyze_request(semaphore, request_str, index):
    async with semaphore:
        retries = 3
        user_prompt = f"Analyze this request:\n\n{request_str}"

        while retries > 0:
            try:
                completion = await client.chat.completions.create(
                    model=MODEL,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0,
                    top_p=0.7,
                    max_tokens=256,
                    response_format={"type": "json_object"}
                )

                reply = completion.choices[0].message.content.strip()

                try:
                    parsed = json.loads(reply)
                except Exception:
                    parsed = {
                        "attack": None,
                        "confidence": 0,
                        "category": "Unknown",
                        "severity": "Unknown",
                        "reason": reply
                    }

                return {
                    "request_number": index,
                    "request": request_str,
                    "analysis": parsed
                }

            except Exception as e:
                retries -= 1
                await asyncio.sleep(2)

        return {
            "request_number": index,
            "request": request_str,
            "analysis": {"error": "Failed after retries"}
        }

async def main():
    try:
        with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            requests_list = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(requests_list)} requests")
    except FileNotFoundError:
        print(f"[!] Error: File '{INPUT_FILE}' not found.")
        return

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    tasks = [
        analyze_request(semaphore, req, i)
        for i, req in enumerate(requests_list, start=1)
    ]

    results = await tqdm.gather(*tasks, desc="Analyzing Requests")
    results.sort(key=lambda x: x["request_number"])
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print(f"\n[+] Processing complete! Results saved to '{OUTPUT_FILE}'.")

if __name__ == "__main__":
    asyncio.run(main())
