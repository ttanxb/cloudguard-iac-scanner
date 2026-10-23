from flask import Flask, render_template, request, jsonify
from pathlib import Path
from scanner import scan

SAMPLES = Path(__file__).parent / "samples"


def create_app():
    app = Flask(__name__)

    @app.route("/", methods=["GET", "POST"])
    def index():
        code, result = "", None
        if request.method == "POST":
            upload = request.files.get("file")
            code = upload.read().decode("utf-8", "ignore") if upload and upload.filename else request.form.get("code", "")
            result = scan(code)
        return render_template("index.html", code=code, result=result)

    @app.route("/sample/<kind>")
    def sample(kind):
        name = "insecure.tf" if kind == "bad" else "secure.tf"
        code = (SAMPLES / name).read_text()
        return render_template("index.html", code=code, result=scan(code))

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        return jsonify(scan(request.get_data(as_text=True)))

    @app.route("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
