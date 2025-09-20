"""Compatibility shims for Flask/Werkzeug changes."""
import flask
from markupsafe import Markup
import werkzeug.urls
from urllib.parse import urlencode

if not hasattr(flask, 'Markup'):
    flask.Markup = Markup

if not hasattr(werkzeug.urls, 'url_encode'):
    def _url_encode(obj, charset='utf-8', sort=False):
        return urlencode(obj, doseq=True)
    werkzeug.urls.url_encode = _url_encode
