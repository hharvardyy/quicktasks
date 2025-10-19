from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="QuickTasks API v3")

# CORS for Next.js dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/tasks")
def list_tasks():
    return [
        {"id": 1, "title": "Buy milk", "status": "open",         "due": "2025-09-15", "tags": ["home"]},
        {"id": 2, "title": "Study DSA", "status": "in_progress", "due": "2025-09-20", "tags": ["school", "cs"]},
        {"id": 3, "title": "Finish design doc", "status": "open","due": "2025-09-14", "tags": ["school"]},
    ]
