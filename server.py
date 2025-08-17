
from flask import Flask, request, jsonify, render_template_string
import requests, os

app = Flask(__name__)
API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")
if not API_KEY:
    raise ValueError("Missing SAFE_BROWSING_API_KEY")

API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

HTML_PAGE = """<html><body><h2>Google Safe Browsing URL Checker</h2>
<form method="POST" action="/check">
<input type="text" name="url" placeholder="Enter URL" required>
<button type="submit">Check URL</button>
</form>
{% if result %}<p>{{ result.status }}</p><pre>{{ result.details }}</pre>{% endif %}
</body></html>"""

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
