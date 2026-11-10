"""Test fixture: intentionally unsafe code for exercising the SAST scanners."""

import hashlib
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/user")
def user():
    connection = sqlite3.connect("fixture.db")
    name = request.args.get("name", "")
    rows = connection.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
    return {"rows": rows}


@app.route("/load", methods=["POST"])
def load():
    document = yaml.load(request.data)
    session = pickle.loads(request.get_data())
    return {"document": str(document), "session": str(session)}


def weak_digest(value):
    return hashlib.md5(value.encode()).hexdigest()


def calculate(expression):
    return eval(expression)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
