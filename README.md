# TruthStamp Phase 2 — Next.js + Tailwind + shadcn UI (Render-ready)

This repo includes:
- **FastAPI backend** (provenance + metadata + PDF report)
- **Next.js web UI** (Tailwind + shadcn-style components)

## Deploy on Render (Free) using Blueprint
1) Push this repo to GitHub.
2) Render Dashboard → **New +** → **Blueprint** → select your repo → **Apply**.
3) Render deploys:
   - `truthstamp-api`
   - `truthstamp-web`

## IMPORTANT: set Web → API URL
After API deploys:
1) Open `truthstamp-api` → copy its public URL.
2) Render → `truthstamp-web` → Environment:
   - `NEXT_PUBLIC_API_URL` = your API URL
3) Redeploy `truthstamp-web`.

## Local run (optional)
Backend:
```bash
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Web:
```bash
cd web
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

Open http://localhost:3000
