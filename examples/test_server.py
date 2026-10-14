"""Local test target for ParamTrace.

Hidden parameters on "/":
  admin     -> 403 Forbidden           (status change)
  redirect  -> 302 to "/"              (status change)
  debug     -> extra debug block       (size change)
  q         -> echoes the value back   (size change + reflection)

"/dynamic" has the same parameters but its page size changes on every
request (random padding), to test --tolerance and false positives.

Run:  python test_server.py
"""
import html
import random

from flask import Flask, Response, request

app = Flask(__name__)

PAGE = "<html><body><h1>ParamTrace test target</h1><p>Nothing to see here.</p></body></html>"


def build(extra_noise=False):
    # request.values merges query string (GET) and form body (POST)
    v = request.values

    if "admin" in v:
        return Response("Forbidden", status=403)
    if "redirect" in v:
        return Response("", status=302, headers={"Location": "/"})

    body = PAGE
    if extra_noise:
        body += "<!-- " + "x" * random.randint(0, 30) + " -->"
    if "debug" in v:
        body += "<pre>" + "DEBUG INFO: internal state dump\n" * 10 + "</pre>"
    if "q" in v:
        body += "<p>You searched for: " + html.escape(v["q"]) + "</p>"
    return body


@app.route("/", methods=["GET", "POST"])
def index():
    return build()


@app.route("/dynamic", methods=["GET", "POST"])
def dynamic():
    return build(extra_noise=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
