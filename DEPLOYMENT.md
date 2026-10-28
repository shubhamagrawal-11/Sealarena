# SealArena: GitHub & Render Deployment Guide

This guide walks you through pushing the SealArena codebase to GitHub and deploying the live Cyber SOC Operations Dashboard onto Render for judges to access via a public HTTPS URL.

---

## 1. Push to GitHub

### Step 1: Open PowerShell or Terminal
Make sure you are in the project folder:
```powershell
cd "d:\Hack in Hills\Sealarena"
```

### Step 2: Create a New GitHub Repository
1. Go to [https://github.com/new](https://github.com/new) in your browser.
2. Set **Repository Name** to: `sealarena` (or your preferred name).
3. Set visibility to **Public** (or **Private**).
4. Leave **"Initialize this repository with a README"** **UNCHECKED** (we already have a complete README).
5. Click **"Create repository"**.

### Step 3: Link and Push Code
Run the following commands in your terminal (replace `<YOUR_GITHUB_USERNAME>` with your GitHub username):
```bash
# Link your remote repository
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/sealarena.git

# Set main branch
git branch -M main

# Push all files to GitHub
git push -u origin main
```

---

## 2. Deploy on Render (Free & Instant)

Render offers free web service hosting and automatically provisions public SSL (`https://...`).

### Method A: Connect Repository (Recommended)
1. Go to [https://dashboard.render.com](https://dashboard.render.com) and sign in.
2. Click **"New +"** in the top navigation bar and select **"Web Service"**.
3. Choose **"Build and deploy from a Git repository"** and click **Next**.
4. Select your **`sealarena`** repository from the list (if not shown, click "Configure account" to grant access).
5. Fill in the deployment settings:
   - **Name**: `sealarena-soc` (or any name you prefer)
   - **Region**: Oregon (US West) or closest to you
   - **Branch**: `main`
   - **Root Directory**: *(leave blank)*
   - **Runtime**: **Python**
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn src.dashboard.main:app --host 0.0.0.0 --port $PORT`
   - **Plan**: **Free**
6. Click **"Deploy Web Service"**.

---

### Method B: Deploy with Docker on Render
If you prefer running inside the Docker container on Render:
1. In the Web Service configuration, select **Runtime: Docker**.
2. Render will automatically detect the root [`Dockerfile`](file:///d:/Hack%20in%20Hills/Sealarena/Dockerfile).
3. Click **"Deploy Web Service"**.

---

## 3. Verify Live Deployment

Once Render finishes building (usually 1-2 minutes):
1. You will receive a live URL: `https://sealarena-soc.onrender.com`.
2. Open the URL in your browser.
3. You will see the complete Cyber SOC Dashboard live on the web:
   - **⚡ TRY TO BREAK IT**: Runs the 9-vector penetration test live in cloud memory.
   - **🚨 SIMULATE TAMPER**: Interactively demonstrates cryptographic tamper detection.
   - **🏆 JUDGE EVALUATION MATRIX**: Displays all 6 objectives for remote judges!
