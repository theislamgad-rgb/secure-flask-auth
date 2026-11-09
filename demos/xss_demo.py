"""Reflected/stored XSS: unescaped output vs. auto-escaped output.

Renders a comment into HTML two ways and shows what a browser would receive.
Run:  python demos/xss_demo.py
"""
from flask import Flask, render_template_string

app = Flask(__name__)

# Marking user input as "safe" tells Jinja NOT to escape it: this is the bug.
VULNERABLE_TEMPLATE = "<p>Comment: {{ comment|safe }}</p>"
# Jinja2 auto-escapes by default for HTML templates; this is the fix.
FIXED_TEMPLATE = "<p>Comment: {{ comment }}</p>"


def render_vulnerable(comment: str) -> str:
    with app.app_context():
        return render_template_string(VULNERABLE_TEMPLATE, comment=comment)


def render_fixed(comment: str) -> str:
    with app.app_context():
        return render_template_string(FIXED_TEMPLATE, comment=comment)


if __name__ == "__main__":
    payload = '<img src=x onerror="alert(document.cookie)">'
    print("VULNERABLE:", render_vulnerable(payload))
    print("FIXED:     ", render_fixed(payload))
    print("\nIn the fixed output the markup is inert text. Defence in depth: the app's")
    print("Content-Security-Policy also blocks inline event handlers and scripts.")
