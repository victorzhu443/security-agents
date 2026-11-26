from flask import Flask

app = Flask(__name__)


@app.get("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    # Local development only; production runs `gunicorn -b 127.0.0.1:8080 app:app`
    # behind the ingress, never the dev server.
    app.run(host="127.0.0.1", port=8080)
