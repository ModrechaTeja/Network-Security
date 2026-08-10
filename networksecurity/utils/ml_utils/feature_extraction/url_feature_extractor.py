"""
Extracts the same 30 lexical/host/page-based features used to train
final_model/model.pkl, directly from a raw URL string, so a single
URL can be scored without needing a pre-built CSV row.

Feature order MUST match data_schema/schema.yaml (minus the Result column).

Honesty note on limitations:
  - 9 features are pure URL-string features (always reliable).
  - 4 features need a DNS/WHOIS lookup (usually reliable, can time out).
  - 12 features need to fetch and parse the live page (best-effort; if the
    fetch fails, they fall back to a neutral 0 and a warning is recorded).
  - 5 features (web_traffic, Page_Rank, Google_Index,
    Links_pointing_to_page, Statistical_report) relied on third-party
    services that are discontinued or unreliable today (e.g. Alexa rank,
    Google's public PageRank API). These are set to a fixed neutral value
    (0) and always reported as unavailable rather than guessed.
"""

import re
import sys
import socket
import ipaddress
from urllib.parse import urlparse

import requests

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging

try:
    import whois
except Exception:
    whois = None

try:
    import dns.resolver
except Exception:
    dns = None

from bs4 import BeautifulSoup

# Exact column order expected by the preprocessor / model (schema.yaml minus Result)
FEATURE_ORDER = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report",
]

SHORTENERS = {
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co",
    "tinyurl.com", "tr.im", "is.gd", "cli.gs", "yfrog.com", "migre.me",
    "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl", "snipurl.com",
    "short.to", "budurl.com", "ping.fm", "post.ly", "just.as", "bkite.com",
    "snipr.com", "fic.kr", "loopt.us", "doiop.com", "short.ie", "kl.am",
    "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "rebrand.ly",
}

FETCH_TIMEOUT = 5  # seconds — keep single-URL checks fast


class URLFeatureExtractor:
    """Builds the 30-feature vector for a raw URL, in the model's expected order."""

    def extract_features(self, url: str):
        try:
            warnings = []
            parsed = urlparse(url if "://" in url else "http://" + url)
            hostname = parsed.hostname or ""
            features = {}

            # ---- Tier A: pure URL string (always reliable) ----
            features["having_IP_Address"] = self._having_ip_address(hostname)
            features["URL_Length"] = self._url_length(url)
            features["Shortining_Service"] = self._shortening_service(hostname)
            features["having_At_Symbol"] = -1 if "@" in url else 1
            features["double_slash_redirecting"] = self._double_slash(url)
            features["Prefix_Suffix"] = -1 if "-" in hostname else 1
            features["having_Sub_Domain"] = self._sub_domain(hostname)
            features["port"] = self._port_check(parsed)
            features["HTTPS_token"] = -1 if "https" in hostname.lower() else 1

            # ---- Tier B: DNS / WHOIS (best-effort, can fail) ----
            whois_record = None
            if whois is not None:
                try:
                    whois_record = whois.whois(hostname)
                except Exception:
                    warnings.append("WHOIS lookup failed — used neutral fallback for registration/age/abnormal-URL features.")

            features["Domain_registeration_length"] = self._registration_length(whois_record)
            features["age_of_domain"] = self._domain_age(whois_record)
            features["Abnormal_URL"] = self._abnormal_url(hostname, whois_record)
            features["DNSRecord"] = self._dns_record(hostname, warnings)

            # ---- Tier C: live page fetch + parse (best-effort) ----
            html, final_url, ssl_ok, redirect_count = self._fetch_page(url, warnings)
            soup = BeautifulSoup(html, "html.parser") if html else None

            features["SSLfinal_State"] = self._ssl_state(parsed.scheme, ssl_ok)
            features["Favicon"] = self._favicon(soup, hostname) if soup else 0
            features["Request_URL"] = self._request_url(soup, hostname) if soup else 0
            features["URL_of_Anchor"] = self._url_of_anchor(soup, hostname) if soup else 0
            features["Links_in_tags"] = self._links_in_tags(soup, hostname) if soup else 0
            features["SFH"] = self._sfh(soup, hostname) if soup else 0
            features["Submitting_to_email"] = self._submitting_to_email(soup) if soup else 0
            features["Redirect"] = self._redirect_score(redirect_count)
            features["on_mouseover"] = self._script_pattern(html, r"onmouseover") if html else 0
            features["RightClick"] = self._script_pattern(html, r"event\.button\s*==\s*2|contextmenu") if html else 0
            features["popUpWidnow"] = self._script_pattern(html, r"window\.open|prompt\(") if html else 0
            features["Iframe"] = -1 if (soup and soup.find_all("iframe")) else 1 if soup else 0

            # ---- Tier D: discontinued/unavailable third-party services ----
            for feat in ["web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"]:
                features[feat] = 0
            warnings.append(
                "web_traffic, Page_Rank, Google_Index, Links_pointing_to_page, and Statistical_report "
                "relied on services that are discontinued or unreliable today (e.g. Alexa rank, Google's "
                "public PageRank API). These were set to a neutral value and were not measured."
            )

            ordered = {k: int(features[k]) for k in FEATURE_ORDER}
            return ordered, warnings

        except Exception as e:
            raise NetworkSecurityException(e, sys)

    # ---------- Tier A helpers ----------
    def _having_ip_address(self, hostname):
        try:
            ipaddress.ip_address(hostname)
            return -1
        except ValueError:
            return 1

    def _url_length(self, url):
        n = len(url)
        if n < 54:
            return 1
        if n <= 75:
            return 0
        return -1

    def _shortening_service(self, hostname):
        return -1 if hostname.lower() in SHORTENERS else 1

    def _double_slash(self, url):
        scheme_end = url.find("://")
        rest = url[scheme_end + 3:] if scheme_end != -1 else url
        return -1 if "//" in rest else 1

    def _sub_domain(self, hostname):
        host = hostname.lower()
        if host.startswith("www."):
            host = host[4:]
        dots = host.count(".")
        if dots <= 1:
            return 1
        if dots == 2:
            return 0
        return -1

    def _port_check(self, parsed):
        try:
            port = parsed.port
        except ValueError:
            return -1
        standard = {None, 80, 443}
        return 1 if port in standard else -1

    # ---------- Tier B helpers ----------
    def _registration_length(self, w):
        try:
            exp = w.expiration_date
            create = w.creation_date
            if isinstance(exp, list):
                exp = exp[0]
            if isinstance(create, list):
                create = create[0]
            days = (exp - create).days
            return 1 if days >= 365 else -1
        except Exception:
            return 0

    def _domain_age(self, w):
        try:
            from datetime import datetime
            create = w.creation_date
            if isinstance(create, list):
                create = create[0]
            age_days = (datetime.now() - create).days
            return 1 if age_days >= 180 else -1
        except Exception:
            return 0

    def _abnormal_url(self, hostname, w):
        try:
            registrant_host = (w.domain_name if not isinstance(w.domain_name, list) else w.domain_name[0]) or ""
            return 1 if hostname.lower() in registrant_host.lower() else -1
        except Exception:
            return 0

    def _dns_record(self, hostname, warnings):
        if dns is None:
            warnings.append("DNS resolver library unavailable — DNSRecord set to neutral fallback.")
            return 0
        try:
            dns.resolver.resolve(hostname, "A")
            return 1
        except Exception:
            return -1

    # ---------- Tier C helpers ----------
    def _fetch_page(self, url, warnings):
        try:
            resp = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
            ssl_ok = resp.url.startswith("https://")
            return resp.text, resp.url, ssl_ok, len(resp.history)
        except Exception:
            warnings.append("Could not fetch the live page (timeout, blocked, or site down) — page-content features set to neutral fallback.")
            return None, url, False, 0

    def _ssl_state(self, scheme, ssl_ok):
        if scheme == "https" and ssl_ok:
            return 1
        if scheme == "https" and not ssl_ok:
            return 0
        return -1

    def _favicon(self, soup, hostname):
        try:
            link = soup.find("link", rel=lambda v: v and "icon" in v.lower())
            if not link or not link.get("href"):
                return 1
            href = link["href"]
            if href.startswith("http"):
                return 1 if hostname in href else -1
            return 1
        except Exception:
            return 0

    def _external_ratio(self, tags, attr, hostname):
        total, external = 0, 0
        for tag in tags:
            val = tag.get(attr)
            if not val or val.startswith("#") or val.startswith("mailto:"):
                continue
            total += 1
            if val.startswith("http") and hostname not in val:
                external += 1
        if total == 0:
            return 1
        pct = external / total
        if pct < 0.22:
            return 1
        if pct <= 0.61:
            return 0
        return -1

    def _request_url(self, soup, hostname):
        tags = soup.find_all(["img", "script"]) + soup.find_all("link")
        return self._external_ratio(tags, "src", hostname) if any(t.get("src") for t in tags) else self._external_ratio(soup.find_all("img"), "src", hostname)

    def _url_of_anchor(self, soup, hostname):
        return self._external_ratio(soup.find_all("a"), "href", hostname)

    def _links_in_tags(self, soup, hostname):
        tags = soup.find_all(["meta", "script", "link"])
        return self._external_ratio(tags, "href", hostname) if any(t.get("href") for t in tags) else self._external_ratio(tags, "src", hostname)

    def _sfh(self, soup, hostname):
        try:
            form = soup.find("form")
            if not form or not form.get("action"):
                return -1
            action = form["action"]
            if action.strip() in ("", "about:blank"):
                return -1
            if action.startswith("http") and hostname not in action:
                return 0
            return 1
        except Exception:
            return 0

    def _submitting_to_email(self, soup):
        try:
            forms = soup.find_all("form")
            for f in forms:
                action = f.get("action", "")
                if "mailto:" in action:
                    return -1
            return 1
        except Exception:
            return 0

    def _redirect_score(self, count):
        if count <= 1:
            return 1
        if count <= 3:
            return 0
        return -1

    def _script_pattern(self, html, pattern):
        return -1 if re.search(pattern, html, re.IGNORECASE) else 1