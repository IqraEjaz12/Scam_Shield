from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from urllib.parse import urlparse

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for


BASE_DIR = Path(__file__).resolve().parent
DB = BASE_DIR / "database.db"

app = Flask(__name__)
app.secret_key = os.environ.get("SCAM_SHIELD_SECRET") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with closing(get_db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_id TEXT UNIQUE NOT NULL,
                student_name TEXT NOT NULL,
                company TEXT NOT NULL,
                issue_date TEXT
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                score INTEGER,
                verdict TEXT,
                findings TEXT NOT NULL DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(checks)")
        }
        if "findings" not in columns:
            conn.execute(
                "ALTER TABLE checks ADD COLUMN findings TEXT NOT NULL DEFAULT '[]'"
            )
        conn.commit()


SUSPICIOUS_WORDS = [
    "login", "verify", "free", "bonus", "urgent", "payment",
    "secure", "account", "fee", "winner", "claim", "offer",
]
SUSPICIOUS_TLDS = (".xyz", ".top", ".tk", ".click", ".work", ".loan", ".gq", ".ml")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly")
FREE_MAIL = ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com")
DISPOSABLE = ("mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com")


def verdict_from_score(score):
    if score >= 60:
        return "HIGH RISK"
    if score >= 30:
        return "REVIEW"
    return "LOW RISK"


def times_reported(value):
    with closing(get_db()) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM reports WHERE value = ?", (value,)
        ).fetchone()[0]


def in_blacklist(kind, value):
    with closing(get_db()) as conn:
        row = conn.execute(
            "SELECT reason FROM blacklist WHERE type = ? AND value = ?",
            (kind, value),
        ).fetchone()
    return row["reason"] if row else None


def parse_url(raw):
    url = raw.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        parsed.port
    except ValueError:
        return None, None
    if (
        parsed.scheme not in ("http", "https")
        or not host
        or "." not in host
        or parsed.username is not None
        or parsed.password is not None
        or any(char.isspace() for char in host)
    ):
        return None, None
    return parsed, host


def is_valid_email(email):
    if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return False
    local, domain = email.rsplit("@", 1)
    return (
        len(local) <= 64
        and len(domain) <= 253
        and all(part and len(part) <= 63 for part in domain.split("."))
        and "." in domain
    )


def check_url(raw):
    if len(raw) > 2048:
        return 100, ["URL is longer than the 2,048-character limit."]
    parsed, host = parse_url(raw)
    if parsed is None:
        return 100, ["The URL format is invalid. Enter a domain or a valid HTTP/HTTPS URL."]

    score, reasons = 0, []
    blacklist_host = host[4:] if host.startswith("www.") else host
    reason = in_blacklist("url", blacklist_host)
    if reason:
        return 100, ["Blocklist match: " + reason]

    if parsed.scheme != "https":
        score += 20
        reasons.append("No HTTPS: the connection is not encrypted.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        score += 30
        reasons.append("The website uses a numeric IP address instead of a domain name.")
    if len(raw) > 75:
        score += 10
        reasons.append("The URL is unusually long.")
    if host.count(".") > 3:
        score += 15
        reasons.append("The domain contains an unusually high number of subdomains.")
    if host.count("-") >= 3:
        score += 10
        reasons.append("The domain contains an unusually high number of hyphens.")
    if host in SHORTENERS:
        score += 15
        reasons.append("The URL uses a link shortener that hides its final destination.")
    if "xn--" in host:
        score += 20
        reasons.append("The domain uses Punycode, which can encode look-alike characters.")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append("The domain uses an extension that this scanner flags for review.")

    hits = [word for word in SUSPICIOUS_WORDS if word in raw.lower()]
    if hits:
        score += min(30, 10 * len(hits))
        reasons.append("Flagged keywords found in the URL: " + ", ".join(hits))

    reports = times_reported(blacklist_host)
    if reports:
        score += 25
        reasons.append(f"Previous user reports: this domain has {reports} report(s) in this app.")

    return min(score, 100), reasons


def check_email(raw):
    email = raw.strip().lower()
    if not is_valid_email(email):
        return 100, ["The email address format is invalid."]

    score, reasons = 0, []
    local, domain = email.rsplit("@", 1)
    reason = in_blacklist("email", email)
    if reason:
        return 100, ["Blocklist match: " + reason]

    if domain in DISPOSABLE:
        score += 40
        reasons.append("Disposable email provider: this address uses a temporary email service.")
    if domain in FREE_MAIL:
        score += 25
        reasons.append("Free email provider: this address is not on a company-owned domain.")
        if any(word in local for word in ("hr", "career", "job", "recruit", "internship", "offer")):
            score += 15
            reasons.append("Recruiting-style address on a free email provider: independently confirm the sender.")
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append("The email domain uses an extension that this scanner flags for review.")
    if sum(char.isdigit() for char in local) >= 4:
        score += 10
        reasons.append("The email account name contains an unusually high number of digits.")

    reports = times_reported(email)
    if reports:
        score += 25
        reasons.append(f"Previous user reports: this email has {reports} report(s) in this app.")

    return min(score, 100), reasons


def extract_certificate_id(text):
    labelled = re.search(
        r"\b(?:certificate|cert|credential|verification)\s*"
        r"(?:id|no\.?|number|#)\s*[:#-]?\s*"
        r"([A-Z0-9][A-Z0-9/_-]{3,})\b",
        text,
        re.IGNORECASE,
    )
    if labelled:
        return labelled.group(1).rstrip("-_/")
    labelled = re.search(
        r"\b(?:ID|No\.?|Number)\s*[:#-]\s*"
        r"([A-Z0-9][A-Z0-9/_-]{3,})\b",
        text,
        re.IGNORECASE,
    )
    if labelled:
        return labelled.group(1).rstrip("-_/")
    prefixed = re.search(
        r"\b(?:CERT(?:IFICATE)?|CRED|INTERN)[\s:#-]*"
        r"[A-Z0-9][A-Z0-9/_-]{2,}\b",
        text,
        re.IGNORECASE,
    )
    return prefixed.group(0).strip(" :#").upper() if prefixed else ""


def check_certificate(cert_id, name, certificate_text="", ocr_confidence=100):
    certificate_text = certificate_text.strip()
    extracted_id = extract_certificate_id(certificate_text)
    if not cert_id:
        cert_id = extracted_id
    if not cert_id and not certificate_text:
        return 0, ["Enter a certificate ID or provide certificate image text."]

    score, reasons = 0, []
    if cert_id and extracted_id and cert_id.casefold() != extracted_id.casefold():
        score += 40
        reasons.append(
            f"Certificate ID mismatch: the entered ID {cert_id} differs from the ID read from the image ({extracted_id})."
        )
    with closing(get_db()) as conn:
        row = None
        if cert_id:
            row = conn.execute(
                "SELECT student_name, company, issue_date FROM certificates WHERE cert_id = ?",
                (cert_id.strip().upper(),),
            ).fetchone()

    if not row:
        score = 45
        if cert_id:
            reasons.append(
                f"Certificate ID not found in local records: {cert_id}."
            )
        else:
            reasons.append(
                "Could not identify a certificate ID in the image. Review the recognized text or enter the ID manually."
            )
    else:
        reasons.append(
            "Local record match: this entry has not been independently verified with the certificate issuer."
        )
        if name and name.strip().casefold() != row["student_name"].casefold():
            score += 55
            reasons.append(
                f"Student name mismatch: the entered name ({name.strip()}) does not match the local record ({row['student_name']})."
            )

    if certificate_text:
        if ocr_confidence < 45:
            score += 15
            reasons.append(
                f"Low OCR confidence: the image text recognition confidence was {round(ocr_confidence)}%, so extracted text may be inaccurate."
            )
        lowered_text = certificate_text.casefold()
        suspicious_phrases = (
            ("pay a fee", "Upfront fee language: the certificate text mentions paying a fee."),
            ("processing fee", "Processing fee language: the text mentions an upfront processing fee."),
            ("registration fee", "Registration fee language: the text asks for a registration fee."),
            ("guaranteed job", "Guaranteed job claim: the text promises a job."),
            ("guaranteed placement", "Guaranteed placement claim: the text promises a placement."),
            ("pay now", "Urgent payment request: the text says to pay immediately."),
            ("refundable deposit", "Refundable deposit request: the text asks for a deposit."),
        )
        for phrase, explanation in suspicious_phrases:
            if phrase in lowered_text:
                score += 20
                reasons.append(explanation)

        extracted_emails = sorted(set(re.findall(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            certificate_text,
            re.IGNORECASE,
        )))
        for email in extracted_emails:
            _, email_reasons = check_email(email)
            for email_reason in email_reasons:
                score += 10
                reasons.append(f"Email found in certificate text ({email}): {email_reason}")

        extracted_urls = sorted(set(re.findall(
            r"\b(?:https?://)?(?:www\.)?[A-Z0-9-]+(?:\.[A-Z0-9-]+)+(?:/[^\s]*)?",
            certificate_text,
            re.IGNORECASE,
        )))
        for link in extracted_urls[:5]:
            _, url_reasons = check_url(link.rstrip(".,;:"))
            for url_reason in url_reasons:
                score += 10
                reasons.append(
                    f"URL found in certificate text ({link}): {url_reason}"
                )

    return min(score, 100), reasons


def explain_findings(kind, reasons, certificate_text=""):
    explanations = (
        (
            "Blocklist match:",
            "Reported or blocklisted item",
            "This exact item has a matching entry in this app's local blocklist. "
            "A blocklist match is a strong warning, but the list may be incomplete or outdated.",
            "Do not use the contact details in the message. Verify the organization through its official website.",
        ),
        (
            "No HTTPS:",
            "Website connection is not encrypted",
            "The website connection is not encrypted. This alone does not prove a scam, "
            "but it can expose information you submit.",
            "Do not enter passwords, payment details, or personal documents on this page.",
        ),
        (
            "The website uses a numeric IP address",
            "Website uses a numeric IP address",
            "A numeric IP address instead of a recognizable organization domain is unusual for an official careers site.",
            "Find the employer's website independently and compare its official domain.",
        ),
        (
            "The URL is unusually long",
            "Unusually long web address",
            "An unusually long link can hide its destination or contain tracking and redirect parameters.",
            "Open the organization's homepage directly instead of following this link.",
        ),
        (
            "The domain contains an unusually high number of subdomains",
            "Unexpected number of subdomains",
            "Several subdomains can make a link look like it belongs to a well-known brand when the registrable domain is different.",
            "Check the actual domain immediately before the top-level extension.",
        ),
        (
            "The domain contains an unusually high number of hyphens",
            "A domain with many hyphens can imitate an employer's real domain; it is a weak signal, not proof.",
            "Compare the spelling with the domain published on the employer's official site.",
        ),
        (
            "The URL uses a link shortener",
            "Shortened link hides its destination",
            "A shortened link conceals the final website until it is opened.",
            "Ask the sender for the full official URL and verify it independently.",
        ),
        (
            "The domain uses Punycode",
            "Look-alike domain encoding",
            "Punycode can encode look-alike characters that are difficult to distinguish from ordinary letters.",
            "Do not sign in through this link; navigate to the organization yourself.",
        ),
        (
            "The domain uses an extension",
            "Uncommon domain extension",
            "This extension is sometimes used in low-cost or short-lived campaigns; the extension alone does not prove fraud.",
            "Verify the employer's domain through an independently found official source.",
        ),
        (
            "The email domain uses an extension",
            "Uncommon email domain extension",
            "This extension is sometimes used in low-cost or short-lived campaigns; the extension alone does not prove fraud.",
            "Verify the sender's domain through an independently found official source.",
        ),
        (
            "Flagged keywords found in the URL:",
            "Urgent, account, or payment-related language",
            "The link contains words commonly associated with urgency, account verification, rewards, or payments. "
            "These words are a clue only and may appear on legitimate sites.",
            "Check the destination domain and avoid entering credentials or paying through an unsolicited link.",
        ),
        (
            "Previous user reports:",
            "Previously reported in this app",
            "This item has prior submissions in this app's local report log. Reports are unverified user claims.",
            "Review the report and confirm with the organization before taking action.",
        ),
        (
            "Disposable email provider:",
            "Disposable email address",
            "The sender uses a disposable mailbox that is easy to abandon and is not a stable company identity.",
            "Ask for an email from the employer's official domain and call a number listed on its official website.",
        ),
        (
            "Free email provider:",
            "Personal email provider",
            "A free-mail provider does not establish that the sender represents the company. Small employers may use one legitimately.",
            "Verify the sender using contact details from the organization's official website.",
        ),
        (
            "Recruiting-style address on a free email provider:",
            "Recruiting contact uses a personal email",
            "A job or HR-style sender name on a personal mailbox can impersonate a recruiting team.",
            "Do not pay fees or share documents until the employer confirms the offer through an official channel.",
        ),
        (
            "The email account name contains an unusually high number of digits",
            "Unusual email account name",
            "Many digits in the mailbox name can be a weak disposable or impersonation signal, but many legitimate people use digits.",
            "Confirm that the address is published by, or independently confirmed by, the organization.",
        ),
        (
            "Certificate ID not found in local records:",
            "Certificate ID not found in local records",
            "This application's local certificate table has no matching record. It is not a connection to a worldwide issuer database, so absence is not proof of forgery.",
            "Contact the certificate issuer using contact information found independently and ask it to confirm the ID.",
        ),
        (
            "Could not identify a certificate ID in the image",
            "Certificate ID could not be read",
            "The OCR could not confidently recognize a certificate number. Image text recognition may miss small, blurry, rotated, or stylized text.",
            "Type the ID printed on the certificate, or upload a sharper, well-lit image.",
        ),
        (
            "Low OCR confidence:",
            "Low confidence reading the certificate image",
            "The image text recognition was uncertain. Blurry, rotated, low-resolution, or decorative text can be misread.",
            "Review the extracted text carefully and correct the certificate ID before relying on the result.",
        ),
        (
            "Local record match:",
            "Matched a local record (not independently verified)",
            "A local record matched, but this application does not independently authenticate the issuer or the record's source.",
            "Confirm the certificate with the issuing organization's official contact before relying on it.",
        ),
        (
            "Student name mismatch:",
            "Certificate name does not match",
            "The entered name differs from the name in this app's local certificate record.",
            "Recheck the spelling and ask the issuer to confirm the certificate and recipient.",
        ),
        (
            "Certificate ID mismatch:",
            "Entered ID differs from the image",
            "The typed certificate ID differs from the number recognized in the image. OCR can confuse similar-looking characters.",
            "Compare both IDs with the original certificate and contact the issuer before relying on either.",
        ),
        (
            "Upfront fee language:",
            "Certificate text mentions an upfront fee",
            "The certificate text mentions an upfront or processing fee. Requests to pay to obtain a job or certificate deserve careful scrutiny.",
            "Do not pay until you independently verify the issuer and its published fee policy.",
        ),
        (
            "Guaranteed placement claim:",
            "Certificate promises guaranteed placement",
            "Guaranteed placement claims can be used to pressure applicants and should be checked against the issuer's real terms.",
            "Confirm the offer directly with the employer; do not pay for a guaranteed job.",
        ),
        (
            "Guaranteed job claim:",
            "Certificate promises a guaranteed job",
            "Guaranteed job claims can be used to pressure applicants and should be checked against the employer's real hiring process.",
            "Contact the employer through its official careers page before sharing details or paying.",
        ),
        (
            "Urgent payment request:",
            "Certificate text requests immediate payment",
            "Urgent payment language can pressure people to pay before verifying an offer.",
            "Do not pay under pressure. Contact the issuer using independently verified contact details.",
        ),
        (
            "Refundable deposit request:",
            "Certificate text requests a deposit",
            "A deposit request connected to a job or certificate deserves careful verification, even when described as refundable.",
            "Do not send money until you verify the issuer and its published fee policy.",
        ),
        (
            "Email found in certificate text (",
            "Email address found in certificate",
            "An email address appears in the certificate text. Local checks found a concern with that address, but the OCR may have misread it.",
            "Check the spelling and confirm that the address belongs to the organization through its official website.",
        ),
        (
            "URL found in certificate text (",
            "Website link found in certificate",
            "A website link appears in the certificate text. Local checks found a concern with that link, but the OCR may have misread it.",
            "Check the spelling and confirm the URL through the issuer's independently verified website.",
        ),
    )
    findings = []
    seen = set()
    for reason in reasons:
        matched = next(
            (entry for entry in explanations if reason.casefold().startswith(entry[0].casefold())),
            None,
        )
        if matched:
            _, title, explanation, action = matched
        else:
            title = "Scanner signal"
            explanation = (
                "This input did not pass one of the scanner's format or matching checks. "
                "A format problem by itself does not establish that the item is a scam."
            )
            action = "Check the spelling and verify the information using the organization's official contact details."
        key = (reason, explanation)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "title": title.rstrip(":"),
                "evidence": reason,
                "why": explanation,
                "action": action,
            }
        )

    if not findings:
        if kind == "certificate" and certificate_text:
            findings.append(
                {
                    "title": "No specific warning sign found",
                    "evidence": "The certificate text was reviewed by local checks.",
                    "why": "The certificate is not independently verified. A clean local scan cannot prove it is genuine.",
                    "action": "Confirm the ID with the issuer using independently found contact details.",
                }
            )
        else:
            findings.append(
                {
                    "title": "No specific warning sign found",
                    "evidence": "No matching local rule or report was found.",
                    "why": "This scanner uses basic local heuristics, not a live security reputation service. New scams may not be listed.",
                    "action": "Verify the sender and organization independently before sharing information or money.",
                }
            )
    return findings


def translate_legacy_reason(reason):
    fixed_phrases = {
        "HTTPS nahi hai (connection secure nahi).": "No HTTPS: the connection is not encrypted.",
        "Domain ki jagah IP address use hua hai.": "The website uses a numeric IP address instead of a domain name.",
        "URL bohat lamba hai.": "The URL is unusually long.",
        "Bohat zyada subdomains hain.": "The domain contains an unusually high number of subdomains.",
        "Domain mein bohat zyada hyphens (-) hain.": "The domain contains an unusually high number of hyphens.",
        "URL shortener use hua hai, asli link chhupa hua hai.": "The URL uses a link shortener that hides its final destination.",
        "Punycode domain (look-alike domain ho sakta hai).": "The domain uses Punycode, which can encode look-alike characters.",
        "Suspicious domain extension use hua hai.": "The domain uses an extension that this scanner flags for review.",
        "Temporary/disposable email service hai.": "Disposable email provider: this address uses a temporary email service.",
        "Free email hai. Company se official contact par confirm karein.": "Free email provider: this address is not on a company-owned domain.",
        "Free email par HR/job jaisa naam hai; ye scam ka common pattern hai.": "Recruiting-style address on a free email provider: independently confirm the sender.",
        "Email ka format sahi nahi hai.": "The email address format is invalid.",
        "Image se koi certificate ID extract nahi ho saki; OCR text manually review karein.": "Could not identify a certificate ID in the image. Review the recognized text or enter the ID manually.",
    }
    if reason in fixed_phrases:
        return fixed_phrases[reason]

    match = re.fullmatch(r"Blacklist mein hai: (.+)", reason)
    if match:
        return f"Blocklist match: {match.group(1)}"
    match = re.fullmatch(r"Shak wale words mile: (.+)", reason)
    if match:
        return f"Flagged keywords found in the URL: {match.group(1)}"
    match = re.fullmatch(r"Users ne is (domain|email) ko (\d+) baar report kiya hai\.", reason)
    if match:
        return f"Previous user reports: this {match.group(1)} has {match.group(2)} report(s) in this app."
    match = re.fullmatch(r"Email mein bohat zyada digits hain\.", reason)
    if match:
        return "The email account name contains an unusually high number of digits."
    match = re.fullmatch(r"Certificate ID (.+) local directory mein nahi mili\.", reason)
    if match:
        return f"Certificate ID not found in local records: {match.group(1)}."
    match = re.fullmatch(r"Local directory match mila, lekin .+", reason)
    if match:
        return "Local record match: this entry has not been independently verified with the certificate issuer."
    match = re.fullmatch(r"Entered student name (.+) stored record ke naam (.+) se match nahi karta\.", reason)
    if match:
        return f"Student name mismatch: the entered name ({match.group(1)}) does not match the local record ({match.group(2)})."
    match = re.fullmatch(r"Image OCR confidence sirf (\d+)% thi; extracted text ghalat ho sakta hai\.", reason)
    if match:
        return f"Low OCR confidence: the image text recognition confidence was {match.group(1)}%, so extracted text may be inaccurate."
    match = re.fullmatch(r"Entered certificate ID (.+) image se read hui ID (.+) se match nahi karti\.", reason)
    if match:
        return f"Certificate ID mismatch: the entered ID {match.group(1)} differs from the ID read from the image ({match.group(2)})."
    match = re.fullmatch(r"Certificate/job hasil karne ke liye fee maang raha hai\.", reason)
    if match:
        return "Upfront fee language: the certificate text mentions paying a fee."
    match = re.fullmatch(r"Processing fee ka zikr hai; .+", reason)
    if match:
        return "Processing fee language: the text mentions an upfront processing fee."
    match = re.fullmatch(r"Registration fee ka zikr hai; .+", reason)
    if match:
        return "Registration fee language: the text asks for a registration fee."
    match = re.fullmatch(r"Guaranteed job ka claim hai; .+", reason)
    if match:
        return "Guaranteed job claim: the text promises a job."
    match = re.fullmatch(r"Guaranteed placement ka claim hai; .+", reason)
    if match:
        return "Guaranteed placement claim: the text promises a placement."
    match = re.fullmatch(r"Foran payment ka mutalba hai; .+", reason)
    if match:
        return "Urgent payment request: the text says to pay immediately."
    match = re.fullmatch(r"Refundable deposit maanga ja raha hai; .+", reason)
    if match:
        return "Refundable deposit request: the text asks for a deposit."
    match = re.fullmatch(r"Certificate text mein (.+) mila: (.+)", reason)
    if match:
        item, nested_reason = match.groups()
        translated_nested = translate_legacy_reason(nested_reason)
        if "@" in item:
            return f"Email found in certificate text ({item}): {translated_nested or nested_reason}"
        return f"URL found in certificate text ({item}): {translated_nested or nested_reason}"
    return None


@app.errorhandler(413)
def request_too_large(error):
    return jsonify({"error": "The request is too large."}), error.code


@app.route("/")
def home():
    with closing(get_db()) as conn:
        stats = {
            "total": conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0],
            "high_risk": conn.execute(
                "SELECT COUNT(*) FROM checks WHERE score >= 60"
            ).fetchone()[0],
            "reports": conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
            "today": conn.execute(
                "SELECT COUNT(*) FROM checks WHERE date(created_at) = date('now', 'localtime')"
            ).fetchone()[0],
        }
        recent_checks = conn.execute(
            "SELECT type, value, score, verdict, "
            "datetime(created_at, 'localtime') AS created_at FROM checks "
            "ORDER BY id DESC LIMIT 5"
        ).fetchall()
        daily_activity = conn.execute(
            """
            WITH RECURSIVE days(day) AS (
                SELECT date('now', 'localtime', '-6 days')
                UNION ALL
                SELECT date(day, '+1 day') FROM days
                WHERE day < date('now', 'localtime')
            )
            SELECT days.day, COUNT(checks.id) AS total
            FROM days
            LEFT JOIN checks ON date(checks.created_at, 'localtime') = days.day
            GROUP BY days.day ORDER BY days.day
            """
        ).fetchall()
    peak = max((row["total"] for row in daily_activity), default=0)
    chart = [
        {
            "label": row["day"][5:],
            "total": row["total"],
            "height": round(row["total"] / peak * 100) if peak else 0,
        }
        for row in daily_activity
    ]
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=stats,
        recent_checks=recent_checks,
        chart=chart,
    )


@app.route("/check")
def check_page():
    return render_template("check.html", active_page="check")


@app.route("/history")
def history_page():
    kind = request.args.get("type", "all")
    query = request.args.get("q", "").strip()[:100]
    if kind not in ("all", "url", "email", "certificate"):
        kind = "all"
    sql = (
        "SELECT type, value, score, verdict, findings, "
        "datetime(created_at, 'localtime') AS created_at FROM checks WHERE 1 = 1"
    )
    params = []
    if kind != "all":
        sql += " AND type = ?"
        params.append(kind)
    if query:
        sql += " AND value LIKE ?"
        params.append(f"%{query}%")
    sql += " ORDER BY id DESC LIMIT 100"
    with closing(get_db()) as conn:
        checks = [dict(row) for row in conn.execute(sql, params).fetchall()]
        for item in checks:
            try:
                item["findings"] = json.loads(item["findings"] or "[]")
            except json.JSONDecodeError:
                item["findings"] = []
            legacy_reasons = [
                translate_legacy_reason(finding.get("evidence", ""))
                for finding in item["findings"]
            ]
            if any(reason is not None for reason in legacy_reasons):
                reasons = [
                    translated if translated is not None else finding.get("evidence", "")
                    for finding, translated in zip(item["findings"], legacy_reasons)
                ]
                item["findings"] = explain_findings(item["type"], reasons)
        total = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
    return render_template(
        "history.html",
        active_page="history",
        checks=checks,
        total=total,
        selected_type=kind,
        search_query=query,
    )


@app.route("/reports", methods=["GET", "POST"])
def reports_page():
    if request.method == "POST":
        kind = request.form.get("type", "")
        value = request.form.get("value", "").strip()
        description = request.form.get("description", "").strip()
        error = None

        if kind not in ("url", "email", "certificate"):
            error = "Select a valid report type."
        elif not value:
            error = "Enter the item you want to report."
        elif len(value) > 2048 or len(description) > 1000:
            error = "The input exceeds the allowed length."
        elif kind == "url":
            _, host = parse_url(value)
            if host is None:
                error = "Enter a valid website URL to report."
            else:
                value = host[4:] if host.startswith("www.") else host
        elif kind == "email":
            value = value.lower()
            if not is_valid_email(value):
                error = "Enter a valid email address to report."
        elif len(value) > 100:
            error = "The certificate ID is too long."

        if error:
            flash(error, "error")
        else:
            with closing(get_db()) as conn:
                conn.execute(
                    "INSERT INTO reports (type, value, description) VALUES (?, ?, ?)",
                    (kind, value.lower(), description),
                )
                conn.commit()
            flash("Report saved. Thanks for helping the community.", "success")
            return redirect(url_for("reports_page"))

    kind = request.args.get("type", "all")
    query = request.args.get("q", "").strip()[:100]
    if kind not in ("all", "url", "email", "certificate"):
        kind = "all"
    sql = (
        "SELECT type, value, description, "
        "datetime(created_at, 'localtime') AS created_at FROM reports WHERE 1 = 1"
    )
    params = []
    if kind != "all":
        sql += " AND type = ?"
        params.append(kind)
    if query:
        sql += " AND (value LIKE ? OR description LIKE ?)"
        params.extend((f"%{query}%", f"%{query}%"))
    sql += " ORDER BY id DESC LIMIT 100"
    with closing(get_db()) as conn:
        reports = conn.execute(sql, params).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    return render_template(
        "reports.html",
        active_page="reports",
        reports=reports,
        total=total,
        selected_type=kind,
        search_query=query,
    )


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON request."}), 400

    kind = data.get("type")
    value = data.get("value")
    extra = data.get("extra", "")
    certificate_text = data.get("certificate_text", "")
    ocr_confidence = data.get("ocr_confidence", 100)
    if kind not in ("url", "email", "certificate"):
        return jsonify({"error": "Select a valid check type."}), 400
    if not isinstance(value, str):
        return jsonify({"error": "The value must be text."}), 400
    if not isinstance(extra, str):
        return jsonify({"error": "The student name must be text."}), 400
    if not isinstance(certificate_text, str):
        return jsonify({"error": "The recognized certificate text is invalid."}), 400
    if (
        isinstance(ocr_confidence, bool)
        or not isinstance(ocr_confidence, (int, float))
        or not 0 <= ocr_confidence <= 100
    ):
        return jsonify({"error": "OCR confidence must be between 0 and 100."}), 400

    value = value.strip()
    extra = extra.strip()
    certificate_text = certificate_text.strip()
    if len(value) > 2048 or len(extra) > 120 or len(certificate_text) > 10000:
        return jsonify({"error": "The input exceeds the allowed length."}), 400
    if kind == "email" and len(value) > 254:
        return jsonify({"error": "Email addresses must be 254 characters or fewer."}), 400
    if kind == "url" and not value:
        return jsonify({"error": "Enter a website URL."}), 400
    if kind == "url" and parse_url(value)[0] is None:
        return jsonify({"error": "Enter a valid website URL."}), 400
    if kind == "email" and not is_valid_email(value):
        return jsonify({"error": "Enter a valid email address."}), 400
    if kind == "certificate" and len(value) > 100:
        return jsonify({"error": "The certificate ID is too long."}), 400
    if kind == "certificate" and not value and not certificate_text:
        return jsonify({"error": "Enter a certificate ID or upload a certificate image."}), 400

    if kind == "url":
        score, reasons = check_url(value)
    elif kind == "email":
        score, reasons = check_email(value)
    else:
        if not value:
            value = extract_certificate_id(certificate_text)
        if len(value) > 100:
            return jsonify({"error": "The certificate ID is too long."}), 400
        score, reasons = check_certificate(
            value, extra, certificate_text, ocr_confidence
        )
        if not value:
            value = "Certificate image scan"

    verdict = verdict_from_score(score)
    findings = explain_findings(kind, reasons, certificate_text)
    with closing(get_db()) as conn:
        conn.execute(
            "INSERT INTO checks (type, value, score, verdict, findings) VALUES (?, ?, ?, ?, ?)",
            (kind, value, score, verdict, json.dumps(findings, ensure_ascii=False)),
        )
        conn.commit()

    return jsonify(
        {
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "findings": findings,
            "input_value": value,
            "extracted_id": extract_certificate_id(certificate_text)
            if kind == "certificate"
            else "",
            "notice": (
                "A risk score is an indicator, not proof. Checks use local rules and this app's local records."
            ),
        }
    )


@app.route("/api/report", methods=["POST"])
def api_report():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON request."}), 400

    kind = data.get("type")
    value = data.get("value")
    desc = data.get("description", "")
    if kind not in ("url", "email", "certificate"):
        return jsonify({"error": "Select a valid report type."}), 400
    if not isinstance(value, str) or not value.strip():
        return jsonify({"error": "Enter the item you want to report."}), 400
    if not isinstance(desc, str):
        return jsonify({"error": "The report description must be text."}), 400

    value = value.strip().lower()
    desc = desc.strip()
    if len(value) > 2048 or len(desc) > 1000:
        return jsonify({"error": "The report exceeds the allowed length."}), 400
    if kind == "url":
        _, host = parse_url(value)
        if host is None:
            return jsonify({"error": "Enter a valid website URL to report."}), 400
        value = host[4:] if host.startswith("www.") else host
    elif kind == "email":
        if not is_valid_email(value):
            return jsonify({"error": "Enter a valid email address to report."}), 400
    elif len(value) > 100:
        return jsonify({"error": "The certificate ID is too long."}), 400

    with closing(get_db()) as conn:
        conn.execute(
            "INSERT INTO reports (type, value, description) VALUES (?, ?, ?)",
            (kind, value, desc),
        )
        conn.commit()
    return jsonify({"message": "Thank you. Your report has been saved."})


init_db()

if __name__ == "__main__":
    app.run(debug=False)
