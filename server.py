
from flask import Flask, request, jsonify, render_template_string
import requests, os

app = Flask(__name__)
API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")
if not API_KEY:
    raise ValueError("Missing SAFE_BROWSING_API_KEY")

API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>URL Safety Checker</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#f4f6f8; display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:100vh; margin:0; }
        .container { background:white; padding:40px; border-radius:12px; box-shadow:0 8px 20px rgba(0,0,0,0.1); max-width:500px; width:90%; text-align:center; }
        h2 { color:#333; margin-bottom:25px; }
        input[type="text"] { width:80%; padding:12px; border:1px solid #ccc; border-radius:8px; font-size:16px; margin-bottom:20px; }
        button { padding:12px 25px; font-size:16px; border:none; border-radius:8px; background-color:#007BFF; color:white; cursor:pointer; transition:0.3s; }
        button:hover { background-color:#0056b3; }
        pre { background:#f0f0f0; padding:15px; border-radius:8px; text-align:left; overflow-x:auto; }
        .result-safe { color: green; font-weight: bold; }
        .result-unsafe { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔎 Google Safe Browsing URL Checker</h2>
        <form method="POST" action="/check">
            <input type="text" name="url" placeholder="Enter URL here" required>
            <br>
            <button type="submit">Check URL</button>
        </form>
        {% if result %}
            <h3>Result:</h3>
            <p class="{{ 'result-unsafe' if result.status=='❌ Unsafe' else 'result-safe' }}">{{ result.status }}</p>
            {% if show_details %}
                <pre>{{ result.details }}</pre>
            {% endif %}
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def home():
    return render_template_string(HTML_PAGE)

@app.route("/check", methods=["POST"])
def check_url():
    url = request.form.get("url") or (request.json.get("url") if request.is_json else None)
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    payload = {"client":{"clientId":"url-checker","clientVersion":"1.0"},
               "threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                             "platformTypes":["ANY_PLATFORM"],
                             "threatEntryTypes":["URL"],
                             "threatEntries":[{"url":url}]}
              }
    response = requests.post(API_URL, json=payload)
    result_json = response.json()
    if "matches" in result_json:
        output = {"status":"❌ Unsafe","details":result_json["matches"]}
    else:
        output = {"status":"✅ Safe","details":None}

    if request.is_json:
        return jsonify(output)
    return render_template_string(HTML_PAGE, result=output)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
