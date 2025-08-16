from flask import Flask, Response, jsonify

app = Flask(__name__)

# Security headers (HSTS only matters over HTTPS in prod)
@app.after_request
def set_security_headers(resp: Response):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    # conservative CSP; loosen if you add external JS/CSS
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests"
    # explicitly disable legacy XSS filter to avoid weird behavior
    resp.headers["X-XSS-Protection"] = "0"
    return resp

@app.get("/health")
def health():
    return jsonify(status="ok"), 200

@app.get("/")
def index():
    return jsonify(message="Hello from secure Flask on private EC2 behind ALB"), 200

if __name__ == "__main__":
    # For local/dev only. In AWS we’ll run via gunicorn.
    app.run(host="0.0.0.0", port=8000, debug=False)
