# Render Free — Step-by-step (from ZIP to live URL)

## A) What to download
1) Download this ZIP from ChatGPT.
2) Install these on your computer:
   - Git (to push to GitHub)
   - A GitHub account
   - (Optional) Docker (only needed if you want to test locally with Docker)

You do NOT need to install c2patool/exiftool/ffmpeg locally if deploying on Render via Docker.
The API Docker image installs them.

## B) Extract the ZIP
1) Right-click the ZIP → Extract All
2) Open the extracted folder. You should see:
   - backend/
   - frontend/
   - docker/
   - render.yaml
   - requirements.txt

## C) Push to GitHub
### Option 1: GitHub Web Upload (easiest)
1) Create a new repo on GitHub (e.g., truthstamp-phase2)
2) Click **Add file → Upload files**
3) Drag ALL extracted files/folders into the upload area
4) Commit

### Option 2: Git CLI
From inside the extracted folder:
```bash
git init
git add .
git commit -m "TruthStamp Phase 2 Render-ready"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

## D) Deploy on Render with Blueprint
1) Go to Render Dashboard
2) Click **New +**
3) Select **Blueprint**
4) Connect your GitHub account if asked
5) Choose your repo
6) Render detects `render.yaml`
7) Click **Apply**
8) Wait for both services to finish deploying:
   - truthstamp-api
   - truthstamp-ui

## E) Fix the UI → API URL (important)
After deploy:
1) Open the Render Dashboard → truthstamp-api
2) Copy its public URL (something like https://truthstamp-api-xxxx.onrender.com)

Then:
3) Open Render Dashboard → truthstamp-ui → Environment
4) Set:
   - TRUTHSTAMP_API_URL = (your copied API URL)
5) Click **Manual Deploy** (or it may auto redeploy)

## F) Test
1) Open your truthstamp-ui public URL
2) Upload an image
3) Click **Analyze (JSON)** and check:
   - tools.c2patool.available == true
   - tools.exiftool.available == true
4) Click **Generate PDF report** and download it

## G) Notes for Free plan
- Services sleep when idle; first request can be slow.
- Upload limit is set to 25 MB via TRUTHSTAMP_MAX_MB in render.yaml (you can change it).
