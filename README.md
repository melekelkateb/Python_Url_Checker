
# Google Safe Browsing URL Checker

🔎 A simple Python Flask web app that checks if a URL is safe or unsafe using Google Safe Browsing API.  

## Usage

### 1. Run Locally
```bash
git clone https://github.com/melekelkateb/python-url-checker.git
cd python-url-checker
pip install -r requirements.txt
export SAFE_BROWSING_API_KEY="YOUR_GOOGLE_API_KEY"  # Linux / Mac
set SAFE_BROWSING_API_KEY="YOUR_GOOGLE_API_KEY"     # Windows CMD
python server.py
```
Open your browser at `http://localhost:10000`.

### 2. Deploy on Render
1. Connect this repo to Render Web Service
2. Set Environment Variable:
```
SAFE_BROWSING_API_KEY = your_google_api_key
```
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `python server.py`
5. Access your app at `https://your-app.onrender.com`
