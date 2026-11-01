# CyberNova — Production Deployment Guide

This project follows a split production architecture:
- **Frontend**: Hosted on **Vercel** with global CDN edge caching, clean URLs, and dynamic `/api` rewrites.
- **Backend API & WebAuthn RP**: Hosted on **Render** (Node.js Express + FIDO2 Relying Party + SQLite SOC Telemetry).
- **Source Code**: Hosted on **GitHub**.

---

## 1. Live Deployment Details

- **Frontend Live URL**: [https://cybernova-auth.vercel.app](https://cybernova-auth.vercel.app)
- **Backend Default Target**: `https://cybernova-backend.onrender.com`
- **Health Check Endpoint**: `/api/health`

---

## 2. GitHub Setup

If you haven't created the repository on GitHub yet:
1. Go to [github.com/new](https://github.com/new) and create a repository named `Phishing-Resistant-Passwordless-Authentication` (or `cybernova-auth`).
2. Run the following in the project root:
   ```bash
   git remote add origin git@github.com:yashvc7481-spe/Phishing-Resistant-Passwordless-Authentication.git
   git push -u origin main
   ```

---

## 3. Render Backend Deployment

### Option A: 1-Click Blueprint (Recommended)
1. Go to [dashboard.render.com](https://dashboard.render.com).
2. Click **New +** → **Blueprint**.
3. Select your GitHub repository.
4. Render will read `render.yaml` automatically:
   - **Service Name**: `cybernova-backend`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Health Check Path**: `/api/health`
5. Click **Apply**.

### Option B: Manual Web Service
1. Click **New +** → **Web Service**.
2. Select your repository.
3. Configure:
   - **Name**: `cybernova-backend`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
4. In **Environment Variables**, add:
   - `NODE_ENV`: `production`
   - `JWT_SECRET`: *(A long secure random string)*
   - `RP_NAME`: `cyberNova Enterprise Portal`
   - `COOKIE_SAMESITE`: `lax`
5. Click **Deploy Web Service**.

---

## 4. Vercel Frontend Configuration

The frontend is already configured and deployed at:
`https://cybernova-auth.vercel.app`

`vercel.json` automatically rewrites all requests from:
`https://cybernova-auth.vercel.app/api/:match*`
to:
`https://cybernova-backend.onrender.com/api/:match*`

This architecture ensures:
1. First-party cookies are preserved without cross-site blocking in modern browsers (Safari, Chrome).
2. WebAuthn origin and Relying Party ID match the frontend domain seamlessly.
3. No manual CORS issues or hardcoded localhost URLs in client code.
