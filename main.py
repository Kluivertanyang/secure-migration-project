# main.py
from fastapi import FastAPI
from pydantic import BaseModel
from agent import chat_with_agent
from fastapi.responses import FileResponse
from pathlib import Path
# -------------------------------
app = FastAPI()
from fastapi.staticfiles import StaticFiles
import os

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or ["http://127.0.0.1:3000"] for specific origin
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend files
# frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
# app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
# # -------------------------------
# Chat Endpoint
class ChatRequest(BaseModel):
    message: str

@app.post("/api/chat")
def chat(req: ChatRequest):
    response = chat_with_agent(req.message)
    return {"response": response}

# -------------------------------
# Health Check Endpoints
# -------------------------------

@app.get("/health")
def health_check():
    """
    Simple health check endpoint.
    Returns service status.
    """
    return {"status": "ok", "message": "AWS LLM Chat Agent is running"}

@app.get("/")
def root():
    return FileResponse(Path("index.html"))

@app.get("/")
def root():
    """
    Root endpoint for quick testing.
    """
    return {"message": "Welcome to the AWS LLM Chat Agent API"}
