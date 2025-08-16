from flask import Flask, jsonify

app = Flask(__name__)


@app.after_request
def set_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/health")
def health():
    return "OK", 200


@app.get("/")
def index():
    return jsonify(message="hello from private ec2"), 200
