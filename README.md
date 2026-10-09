# UNIGUARD AI — Passive Threat Intelligence

**SIH Problem Statement:** SIH26145  
**Core Architecture:** Passive AI-Powered Cybersecurity Platform for Unidirectional IP Traffic Analysis

---

## Overview

UNIGUARD AI is a passive, line-rate threat intelligence platform designed for strict network isolation environments (optical unidirectional data diodes). Traditional security tools rely on bidirectional probing (ICMP, TCP SYN-ACK handshakes, reverse queries) which alerts adversaries and breaches air-gapped zones. UNIGUARD AI inspects ingress packet flows with **zero active transmission (0 TX)**, using machine learning to classify threats and generate mathematically explainable, immutable forensic evidence.

---

## Key Features

- **Passive Unidirectional Ingress**: Physically constrained optical data-diode ingestion.
- **Explainable AI (XAI)**: Threat classification with real feature attribution weights (entropy, burstiness, inter-arrival jitter).
- **Immutable Forensic Evidence**: Cryptographically chained SHA-256 evidence logs and raw packet slice records.
- **Institutional SaaS UI**: Modern, high-density minimalist interface built with React, TypeScript, Tailwind CSS, and Three.js.
- **FastAPI Engine**: High-performance asynchronous Python backend with live telemetry endpoints.
- **Supabase Integration**: Cloud PostgreSQL schema with Row Level Security (RLS).

---

## Tech Stack

- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS v4, Three.js, Lucide Icons
- **Backend**: Python 3.14, FastAPI, Uvicorn, Pydantic, Scikit-Learn
- **Database & Storage**: Supabase (PostgreSQL 15+), SHA-256 Evidence Ledger

---

## Quick Start

### 1. Backend Setup
```bash
# Set up Python virtual environment
python3 -m venv backend/.venv
./backend/.venv/bin/pip install -r backend/requirements.txt

# Configure environment variables
cp backend/.env.example backend/.env

# Run FastAPI backend
PYTHONPATH=backend ./backend/.venv/bin/uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Setup
```bash
cd frontend
npm install

# Configure environment variables
cp .env.example .env.local

# Run Vite dev server
npm run dev
```

Dashboard is available at: `http://localhost:5173`  
Backend API & Docs: `http://127.0.0.1:8000/docs`

---

## Verification & Testing
```bash
# Run backend test suite
PYTHONPATH=backend ./backend/.venv/bin/pytest backend/tests

# Run frontend build & typecheck
cd frontend && npm run build
```
