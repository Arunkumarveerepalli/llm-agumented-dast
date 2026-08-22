"""
Form and parameter extractor.

Given a fetched HTML page, pulls out every form and every query-parameter
link so the crawler can turn them into Endpoint objects.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from models import Endpoint, Param, ParamSource, FormSpec

# Common CSRF field names DVWA / similar apps use — extend as needed
CSRF_FIELD_CANDIDATES = {"user_token", "csrf_token", "_csrf", "authenticity_token"}


def extract_forms(html: str, page_url: str) -> list[Endpoint]:
    """Parse every <form> on the page into an Endpoint with a FormSpec."""
    soup = BeautifulSoup(html, "html.parser")
    endpoints: list[Endpoint] = []

    for form_tag in soup.find_all("form"):
        action = form_tag.get("action") or page_url
        full_action = urljoin(page_url, action)
        method = (form_tag.get("method") or "GET").upper()

        inputs: list[Param] = []
        submit_fields: dict[str, str] = {}
        csrf_field = None

        for input_tag in form_tag.find_all(["input", "textarea", "select"]):
            name = input_tag.get("name")
            if not name:
                continue
            input_type = input_tag.get("type", "text").lower()
            if input_type in ("submit", "button", "image", "reset"):
                # Not injectable, but many apps (DVWA included) only process
                # the form if this field is present with its exact value —
                # capture it so the scanner can send it unchanged on every
                # request, rather than dropping it and silently never
                # triggering the page's actual logic.
                submit_fields[name] = input_tag.get("value", "")
                continue

            inputs.append(
                Param(
                    name=name,
                    source=ParamSource.FORM,
                    type=input_type,
                    default_value=input_tag.get("value", ""),
                )
            )

            if name in CSRF_FIELD_CANDIDATES:
                csrf_field = name

        form_spec = FormSpec(
            action=full_action,
            method=method,
            inputs=inputs,
            has_csrf_token=csrf_field is not None,
            csrf_field_name=csrf_field,
            submit_fields=submit_fields,
        )

        endpoints.append(
            Endpoint(url=full_action, method=method, params=inputs, form=form_spec)
        )

    return endpoints


def extract_query_param_links(html: str, page_url: str, allowed_netloc: str) -> list[Endpoint]:
    """Parse every <a href> with query params, restricted to the same origin."""
    soup = BeautifulSoup(html, "html.parser")
    endpoints: list[Endpoint] = []

    for a_tag in soup.find_all("a", href=True):
        full_url = urljoin(page_url, a_tag["href"])
        parsed = urlparse(full_url)

        if parsed.netloc != allowed_netloc:
            continue  # stay in-scope, same-origin only
        if not parsed.query:
            continue  # nothing to inject here

        query_params = parse_qs(parsed.query)
        params = [
            Param(name=name, source=ParamSource.QUERY, default_value=values[0] if values else "")
            for name, values in query_params.items()
        ]

        endpoints.append(Endpoint(url=full_url, method="GET", params=params, form=None))

    return endpoints


def extract_links(html: str, page_url: str, allowed_netloc: str) -> list[str]:
    """Return every same-origin link on the page, for the crawler's BFS queue."""
    soup = BeautifulSoup(html, "html.parser")
    links = []

    for a_tag in soup.find_all("a", href=True):
        full_url = urljoin(page_url, a_tag["href"])
        parsed = urlparse(full_url)
        if parsed.netloc == allowed_netloc and parsed.scheme in ("http", "https"):
            links.append(full_url)

    return links