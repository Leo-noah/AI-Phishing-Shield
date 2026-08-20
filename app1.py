# ================================================================
# AI PHISHING SHIELD - FINAL FLASK BACKEND
# ================================================================

from collections import Counter
from urllib.parse import urlparse

import json
import math
import os
import re
import traceback

from flask import Flask, jsonify, request
from flask_cors import CORS

import joblib
import pandas as pd
import tldextract


# ================================================================
# 1. FLASK SETUP
# ================================================================

app = Flask(__name__)
CORS(app)

BLOCKLIST_FILE = "blocked_urls.json"


# ================================================================
# 2. FINAL PROJECT THRESHOLDS
# ================================================================

SAFE_MAX = 20.0
DANGER_MIN = 80.0


# ================================================================
# 3. TLD EXTRACTOR
# ================================================================

extractor = tldextract.TLDExtract(
    suffix_list_urls=None
)


# ================================================================
# 4. DEFAULT FEATURE ORDER
# ================================================================

FEATURE_NAMES = [
    "url_length",
    "domain_len",
    "url_entropy",
    "sub_domain",
    "digit_count",
    "special_chars_count",
    "slash_count",
    "https_flag",
    "domain_entropy",
    "keyword_flag",
    "ip_flag",
    "hyphen_count",
    "query_length",
    "at_flag",
    "subdomain_spoof_flag",
    "path_brand_spoof_flag",
    "has_suspicious_ext",
    "is_in_top_1m",
    "has_redirect_param",
    "is_ugc_domain"
]


# ================================================================
# 5. TRUSTED DOMAINS
# ================================================================

TRUSTED_REGISTERED_DOMAINS = {
    "google.com",
    "facebook.com",
    "paypal.com",
    "canva.com",
    "dropbox.com",
    "microsoft.com",
    "apple.com",
    "youtube.com",
    "amazon.com",
    "twitter.com",
    "linkedin.com",
    "instagram.com",
    "cloudflare.com",
    "wikipedia.org",
    "stackoverflow.com",
    "zoom.us",
    "stripe.com",
    "pypi.org",
    "python.org",
    "bitbucket.org",
    "medium.com",
    "quora.com",
    "reddit.com",
    "twitch.tv",
    "adobe.com",
    "salesforce.com",
    "badssl.com"
}


# ================================================================
# 6. UGC / HOSTING DOMAINS
# ================================================================

UGC_HOSTING_DOMAINS = {
    "github.com",
    "githubusercontent.com",
    "raw.githubusercontent.com",
    "gitlab.com",
    "wsimg.com",
    "appspot.com",
    "github.io",
    "webflow.io",
    "firebaseapp.com",
    "sites.google.com",
    "forms.gle",
    "vercel.app",
    "netlify.app",
    "wordpress.com",
    "weebly.com",
    "wixsite.com",
    "glitch.me",
    "repl.co",
    "mediafire.com",
    "sendspace.com",
    "discordapp.com",
    "jsdelivr.net",
    "web.archive.org",
    "paste.sensio.no",
    "pastefy.app",
    "duckdns.org",
    "yzz.me",
    "eu.cc",
    "temp.sh",
    "boletos-notas.com"
}


# ================================================================
# 7. SENSITIVE BRANDS
# ================================================================

SENSITIVE_BRANDS = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "adobe",
    "dropbox",
    "github",
    "canva",
    "yahoo",
    "outlook",
    "office365",
    "icloud",
    "cloudflare",
    "okta",

    "facebook",
    "instagram",
    "whatsapp",
    "twitter",
    "linkedin",
    "tiktok",
    "snapchat",
    "telegram",
    "discord",
    "reddit",
    "pinterest",

    "paypal",
    "stripe",
    "square",

    "chase",
    "bankofamerica",
    "wellsfargo",
    "citi",
    "hsbc",

    "binance",
    "coinbase",
    "metamask",

    "intuit",
    "revolut",

    "netflix",
    "spotify",
    "steam",
    "roblox",
    "playstation",
    "xbox",
    "twitch",

    "ebay",
    "walmart",
    "shopify",

    "dhl",
    "fedex",
    "usps",

    "wikipedia",
    "stackoverflow",
    "zoom",
    "pypi",

    "docusign",
    "pdffiller",
    "boletos"
]


# ================================================================
# 8. SUSPICIOUS WORDS
# ================================================================

SENSITIVE_WORDS_DOMAIN = {
    "phishing",
    "phish",
    "phishingdemo",
    "fake",
    "spoof",
    "testpage",
    "malware",
    "exploit",
    "payload",
    "hacked",
    "pwned",

    "verify",
    "verification",
    "verif",
    "zweryfikuj",
    "validate",
    "confirm",
    "confirmation",

    "update",
    "reactivate",
    "restore",
    "suspended",
    "unusual",
    "activity",
    "security-check",
    "checkpoint",

    "login",
    "log-in",
    "signin",
    "sign-in",

    "auth",
    "authorize",
    "oauth",

    "credential",
    "password",
    "passcode",
    "account",

    "usr",
    "user",
    "admin",
    "portal",
    "session",

    "paypal",
    "banking",
    "secure",
    "wallet",
    "billing",
    "payment",
    "invoice",
    "transfer",
    "checkout",
    "bank",
    "credit",
    "card",

    "webflow",
    "file",
    "files",
    "download",
    "installer",
    "doc",
    "pdf",
    "nota",
    "boleto",

    "ga",
    "tk",
    "ml",
    "cf",
    "gq",
    "xyz",
    "top",
    "work",
    "club"
}


# ================================================================
# 9. REGEX
# ================================================================

WORD_TOKEN_PATTERN = re.compile(
    r"[a-zA-Z0-9]+"
)

SPECIAL_CHAR_PATTERN = re.compile(
    r"[^a-zA-Z0-9\s]"
)

IP_PATTERN = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
)

SUSPICIOUS_EXT_PATTERN = re.compile(
    r"\.(exe|zip|iso|bin|sh|elf|dll|scr|ps1|msi|apk|rar|7z)$",
    re.IGNORECASE
)


# ================================================================
# 10. LOAD TOP-1M DOMAIN DATABASE
# ================================================================

try:
    TOP_1M_DOMAINS = joblib.load(
        "top_1m_domains.pkl"
    )

    print(
        f"Loaded Whitelist Domain Database "
        f"({len(TOP_1M_DOMAINS):,} domains)"
    )

except Exception as error:

    print(
        f"Whitelist file error: {error}"
    )

    TOP_1M_DOMAINS = (
        TRUSTED_REGISTERED_DOMAINS
        - UGC_HOSTING_DOMAINS
    )


# ================================================================
# 11. LOAD MODEL 2 BUNDLE
# ================================================================

model = None
saved_bundle = None

try:

    saved_bundle = joblib.load(
        "FINAL_HARD_RETRAINED_PHISHING_MODEL.pkl"
    )

    print(
        "Model bundle loaded successfully!"
    )

    # ------------------------------------------------------------
    # IMPORTANT FIX
    # The PKL is a dictionary bundle.
    # Extract the real classifier from ["model"].
    # ------------------------------------------------------------

    if isinstance(saved_bundle, dict):

        print(
            "Bundle keys:",
            list(saved_bundle.keys())
        )

        if "model" not in saved_bundle:

            raise KeyError(
                "The model bundle does not contain a 'model' key."
            )

        model = saved_bundle["model"]

        print(
            "XGBoost classifier extracted from 'model' key"
        )

        # Use saved feature order if available
        if "feature_names" in saved_bundle:

            saved_features = saved_bundle["feature_names"]

            if saved_features:

                FEATURE_NAMES = list(
                    saved_features
                )

                print(
                    f"Loaded saved feature list: "
                    f"{len(FEATURE_NAMES)} features"
                )

        if "threshold" in saved_bundle:
            print(
                "Saved model threshold:",
                saved_bundle["threshold"]
            )

        if "hard_fp_count" in saved_bundle:
            print(
                "Hard FP count:",
                saved_bundle["hard_fp_count"]
            )

        if "hard_fn_count" in saved_bundle:
            print(
                "Hard FN count:",
                saved_bundle["hard_fn_count"]
            )

        if "metrics" in saved_bundle:
            print(
                "Saved metrics:",
                saved_bundle["metrics"]
            )

    else:

        # Fallback if someday the file is a direct classifier
        model = saved_bundle

        print(
            "Direct classifier loaded."
        )


    print(
        "Model type:",
        type(model)
    )

    if hasattr(
        model,
        "n_features_in_"
    ):

        print(
            "Model expected features:",
            model.n_features_in_
        )

except Exception as error:

    print(
        "Model loading error:",
        error
    )

    traceback.print_exc()

    model = None


# ================================================================
# 12. BLOCKLIST FUNCTIONS
# ================================================================

def load_blocklist():

    if not os.path.exists(
        BLOCKLIST_FILE
    ):
        return {}

    try:

        with open(
            BLOCKLIST_FILE,
            "r"
        ) as file:

            return json.load(
                file
            )

    except Exception as error:

        print(
            "[BLOCKLIST LOAD ERROR]",
            error
        )

        return {}


def save_to_blocklist(
    url,
    score
):

    blocklist = load_blocklist()

    blocklist[url] = {
        "danger_score": score
    }

    try:

        with open(
            BLOCKLIST_FILE,
            "w"
        ) as file:

            json.dump(
                blocklist,
                file,
                indent=4
            )

        print(
            "[BLOCKLIST SAVED]",
            url
        )

    except Exception as error:

        print(
            "[BLOCKLIST SAVE ERROR]",
            error
        )


# ================================================================
# 13. ENTROPY
# ================================================================

def get_entropy(text):

    if not text:
        return 0.0

    counts = Counter(
        text
    )

    length = float(
        len(text)
    )

    return -sum(

        count / length
        * math.log2(
            count / length
        )

        for count
        in counts.values()
    )


# ================================================================
# 14. EXTRACT 20 FEATURES
# ================================================================

def extract_intelligent_features(
    row_url
):

    url = str(
        row_url
    ).strip()

    url_lower = (
        url.lower()
    )


    if not url_lower.startswith(
        ("http://", "https://")
    ):

        temp_url = (
            "https://" + url
        )

    else:

        temp_url = url


    try:

        parsed = urlparse(
            temp_url
        )

        domain = (
            parsed.hostname
            if parsed.hostname
            else ""
        )

        path = (
            (parsed.path or "")
            +
            (
                f"?{parsed.query}"
                if parsed.query
                else ""
            )
            +
            (
                f"#{parsed.fragment}"
                if parsed.fragment
                else ""
            )
        )

        query_str = (
            parsed.query
            if parsed.query
            else ""
        )

    except Exception:

        domain = ""
        path = ""
        query_str = ""


    url_length = len(
        url
    )

    domain_len = (
        len(domain)
        if domain
        else url_length
    )

    url_entropy = get_entropy(
        url
    )

    domain_entropy = (
        get_entropy(domain)
        if domain
        else 0.0
    )


    sub_domain = 0
    reg_domain = ""
    is_in_top_1m = 0
    is_ugc_domain = 0


    if domain:

        ext = extractor(
            domain
        )

        reg_domain = (
            f"{ext.domain}.{ext.suffix}"
            .lower()
        )

        sub_domain = (
            len(
                ext.subdomain.split(".")
            )
            if ext.subdomain
            else 0
        )


        if (
            reg_domain
            in UGC_HOSTING_DOMAINS
            or domain.lower()
            in UGC_HOSTING_DOMAINS
        ):
            is_ugc_domain = 1


        if (
            reg_domain
            in TOP_1M_DOMAINS
            and not is_ugc_domain
        ):
            is_in_top_1m = 1


    special_chars_count = (
        len(
            SPECIAL_CHAR_PATTERN.findall(
                path
            )
        )
        if path
        else 0
    )


    digit_count = (
        sum(
            character.isdigit()
            for character
            in path
        )
        if path
        else 0
    )


    slash_count = (
        url.count("/")
    )


    https_flag = (
        1
        if url_lower.startswith(
            "https"
        )
        else 0
    )


    ip_flag = (
        1
        if (
            domain
            and IP_PATTERN.match(
                domain
            )
        )
        else 0
    )


    hyphen_count = (
        domain.count("-")
        if domain
        else 0
    )


    query_length = len(
        query_str
    )


    at_flag = (
        1
        if "@" in url
        else 0
    )


    # ------------------------------------------------------------
    # REDIRECT PARAMETER
    # ------------------------------------------------------------

    has_redirect_param = (
        1
        if any(
            parameter
            in query_str
            for parameter
            in [
                "url=",
                "redirect=",
                "dest=",
                "target=",
                "out=",
                "link="
            ]
        )
        else 0
    )


    # ------------------------------------------------------------
    # SUBDOMAIN SPOOF
    # ------------------------------------------------------------

    subdomain_spoof_flag = 0


    if (
        domain
        and not ip_flag
        and reg_domain
    ):

        ext = extractor(
            domain
        )

        subdomain_part = (
            ext.subdomain.lower()
            if ext.subdomain
            else ""
        )


        if subdomain_part:

            for brand in SENSITIVE_BRANDS:

                if (
                    brand in subdomain_part
                    and brand
                    != ext.domain.lower()
                ):

                    subdomain_spoof_flag = 1
                    break


    # ------------------------------------------------------------
    # PATH BRAND SPOOF
    # ------------------------------------------------------------

    path_brand_spoof_flag = 0


    if (
        path
        and not is_in_top_1m
    ):

        path_lower = (
            path.lower()
        )


        has_credential_intent = any(
            word
            in path_lower
            for word
            in [
                "login",
                "signin",
                "verify",
                "account"
            ]
        )


        for brand in SENSITIVE_BRANDS:

            if (
                brand
                in path_lower
                and has_credential_intent
            ):

                path_brand_spoof_flag = 1
                break


    # ------------------------------------------------------------
    # SUSPICIOUS EXTENSION
    # ------------------------------------------------------------

    has_suspicious_ext = (
        1
        if SUSPICIOUS_EXT_PATTERN.search(
            path
        )
        else 0
    )


    # ------------------------------------------------------------
    # KEYWORD FLAG
    # ------------------------------------------------------------

    tokens = set(
        WORD_TOKEN_PATTERN.findall(
            url_lower
        )
    )


    keyword_flag = (
        1
        if bool(
            tokens
            & SENSITIVE_WORDS_DOMAIN
        )
        else 0
    )


    # ------------------------------------------------------------
    # RETURN FEATURES
    # ------------------------------------------------------------

    return {

        "url_length":
            url_length,

        "domain_len":
            domain_len,

        "url_entropy":
            url_entropy,

        "sub_domain":
            sub_domain,

        "digit_count":
            digit_count,

        "special_chars_count":
            special_chars_count,

        "slash_count":
            slash_count,

        "https_flag":
            https_flag,

        "domain_entropy":
            domain_entropy,

        "keyword_flag":
            keyword_flag,

        "ip_flag":
            ip_flag,

        "hyphen_count":
            hyphen_count,

        "query_length":
            query_length,

        "at_flag":
            at_flag,

        "subdomain_spoof_flag":
            subdomain_spoof_flag,

        "path_brand_spoof_flag":
            path_brand_spoof_flag,

        "has_suspicious_ext":
            has_suspicious_ext,

        "is_in_top_1m":
            is_in_top_1m,

        "has_redirect_param":
            has_redirect_param,

        "is_ugc_domain":
            is_ugc_domain
    }


# ================================================================
# 15. DOMAIN TRUST SCORE
# ================================================================

def evaluate_domain_trust_score(
    url_str
):

    try:

        url_clean = (
            str(url_str)
            .lower()
            .strip()
        )


        if not url_clean.startswith(
            ("http://", "https://")
        ):

            url_clean = (
                "https://" + url_clean
            )


        parsed = urlparse(
            url_clean
        )

        hostname = (
            parsed.hostname
            or ""
        )

        query_str = (
            parsed.query
            or ""
        )

        path_str = (
            parsed.path
            or ""
        )


        # --------------------------------------------------------
        # IP HOST
        # --------------------------------------------------------

        if IP_PATTERN.match(
            hostname
        ):

            return (
                10.0,
                "IP_HOST"
            )


        ext = extractor(
            hostname
        )

        subdomain = (
            ext.subdomain.lower()
            if ext.subdomain
            else ""
        )

        domain_part = (
            ext.domain.lower()
            if ext.domain
            else ""
        )

        suffix = (
            ext.suffix.lower()
            if ext.suffix
            else ""
        )

        registered_domain = (
            f"{domain_part}.{suffix}"
            if (
                domain_part
                and suffix
            )
            else ""
        )


        # --------------------------------------------------------
        # SPOOFED SUBDOMAIN
        # --------------------------------------------------------

        if subdomain:

            for brand in SENSITIVE_BRANDS:

                if (
                    brand
                    in subdomain
                    and brand
                    != domain_part
                ):

                    return (
                        5.0,
                        "SPOOFED_SUBDOMAIN"
                    )


        # --------------------------------------------------------
        # UGC HOST
        # --------------------------------------------------------

        if (
            registered_domain
            in UGC_HOSTING_DOMAINS
            or hostname
            in UGC_HOSTING_DOMAINS
        ):

            return (
                25.0,
                "UGC_HOST"
            )


        # --------------------------------------------------------
        # EXECUTABLE DOWNLOAD
        # --------------------------------------------------------

        if SUSPICIOUS_EXT_PATTERN.search(
            path_str
        ):

            return (
                15.0,
                "EXECUTABLE_DOWNLOAD_RISK"
            )


        # --------------------------------------------------------
        # REDIRECT
        # --------------------------------------------------------

        has_redirect = any(
            parameter
            in query_str
            for parameter
            in [
                "url=",
                "redirect=",
                "dest=",
                "target=",
                "out=",
                "link="
            ]
        )


        # --------------------------------------------------------
        # SUSPICIOUS PATH
        # --------------------------------------------------------

        has_suspicious_path = any(
            word
            in (
                path_str
                + query_str
            )
            for word
            in [
                "login",
                "verify",
                "account",
                "signin",
                "credential",
                "update"
            ]
        )


        # --------------------------------------------------------
        # TRUSTED DOMAIN
        # --------------------------------------------------------

        if (
            registered_domain
            in TOP_1M_DOMAINS
        ):

            if (
                has_redirect
                or has_suspicious_path
            ):

                return (
                    50.0,
                    "SUSPICIOUS_TRUSTED_PATH"
                )


            return (
                90.0,
                "TRUSTED_DOMAIN"
            )


        # --------------------------------------------------------
        # PATH BRAND
        # --------------------------------------------------------

        if has_suspicious_path:

            for brand in SENSITIVE_BRANDS:

                if (
                    brand
                    in path_str.lower()
                    and brand
                    != domain_part
                ):

                    return (
                        20.0,
                        "SUSPICIOUS_PATH_BRAND"
                    )


    except Exception as error:

        print(
            "[DOMAIN TRUST ERROR]",
            error
        )


    return (
        50.0,
        "UNKNOWN_DOMAIN"
    )


# ================================================================
# 16. HEALTH CHECK
# ================================================================

@app.route(
    "/",
    methods=["GET"]
)
def health_check():

    return jsonify({

        "status":
            "AI Phishing Shield backend is running",

        "model_loaded":
            model is not None,

        "model_type":
            str(
                type(model)
            ),

        "features":
            len(
                FEATURE_NAMES
            ),

        "safe_threshold":
            SAFE_MAX,

        "danger_threshold":
            DANGER_MIN
    })


# ================================================================
# 17. PREDICTION ENDPOINT
# ================================================================

@app.route(
    "/predict",
    methods=["POST"]
)
def predict_url():

    try:

        # --------------------------------------------------------
        # REQUEST
        # --------------------------------------------------------

        data = request.get_json(
            silent=True
        )


        if (
            not data
            or "url"
            not in data
        ):

            return jsonify({
                "error":
                    "No URL provided"
            }), 400


        target_url = str(
            data["url"]
        ).strip()


        if not target_url:

            return jsonify({
                "error":
                    "Empty URL"
            }), 400


        print("\n")
        print("=" * 70)

        print(
            "[REQUEST URL]",
            target_url
        )


        # --------------------------------------------------------
        # BLOCKLIST CACHE
        # --------------------------------------------------------

        blocklist = (
            load_blocklist()
        )


        if (
            target_url
            in blocklist
        ):

            cached_score = (
                blocklist[
                    target_url
                ][
                    "danger_score"
                ]
            )


            print(
                "[BLOCKLIST CACHE HIT]"
            )


            return jsonify({

                "url":
                    target_url,

                "danger_score":
                    cached_score,

                "safe_score":
                    round(
                        100.0
                        - cached_score,
                        2
                    ),

                "trust_status":
                    "BLOCKLIST_CACHE",

                "status":
                    "DANGEROUS",

                "redirect":
                    "blocked.html",

                "source":
                    "blocklist_cache"
            })


        # --------------------------------------------------------
        # MODEL CHECK
        # --------------------------------------------------------

        if model is None:

            return jsonify({
                "error":
                    "Machine learning model not loaded"
            }), 500


        if not hasattr(
            model,
            "predict_proba"
        ):

            return jsonify({

                "error":
                    "Loaded object is not an XGBoost classifier",

                "model_type":
                    str(
                        type(model)
                    )

            }), 500


        # --------------------------------------------------------
        # FEATURE EXTRACTION
        # --------------------------------------------------------

        features_dict = (
            extract_intelligent_features(
                target_url
            )
        )


        missing_features = [
            feature
            for feature
            in FEATURE_NAMES
            if feature
            not in features_dict
        ]


        if missing_features:

            raise ValueError(
                f"Missing features: {missing_features}"
            )


        features_df = pd.DataFrame(

            [[
                features_dict[
                    feature_name
                ]
                for feature_name
                in FEATURE_NAMES
            ]],

            columns=
                FEATURE_NAMES
        )


        features_df = (
            features_df.astype(
                "float32"
            )
        )


        print(
            "[FEATURE SHAPE]",
            features_df.shape
        )

        print(
            "[FEATURE COLUMNS]",
            list(
                features_df.columns
            )
        )


        # --------------------------------------------------------
        # XGBOOST PREDICTION
        # --------------------------------------------------------

        prediction = (
            model.predict_proba(
                features_df
            )
        )


        ml_probability = (
            prediction[0][1]
        )


        ml_danger_score = (
            float(
                ml_probability
            )
            * 100.0
        )


        ml_safe_score = (
            100.0
            - ml_danger_score
        )


        print(
            "[ML DANGER SCORE]",
            round(
                ml_danger_score,
                2
            )
        )


        # --------------------------------------------------------
        # DOMAIN TRUST
        # --------------------------------------------------------

        (
            domain_safe_score,
            trust_status

        ) = evaluate_domain_trust_score(
            target_url
        )


        print(
            "[DOMAIN TRUST STATUS]",
            trust_status
        )

        print(
            "[DOMAIN SAFE SCORE]",
            domain_safe_score
        )


        # --------------------------------------------------------
        # HYBRID SCORE
        # --------------------------------------------------------

        if (
            trust_status
            == "TRUSTED_DOMAIN"
        ):

            final_safe_score = (

                0.7
                * ml_safe_score

                +

                0.3
                * domain_safe_score
            )


        elif trust_status in (

            "SPOOFED_SUBDOMAIN",
            "IP_HOST",
            "UGC_HOST",
            "EXECUTABLE_DOWNLOAD_RISK",
            "SUSPICIOUS_PATH_BRAND"

        ):

            final_safe_score = min(

                domain_safe_score,

                ml_safe_score
            )


        else:

            final_safe_score = (

                0.85
                * ml_safe_score

                +

                0.15
                * domain_safe_score
            )


        final_danger_score = round(

            100.0
            - final_safe_score,

            2
        )


        print(
            "[FINAL DANGER SCORE]",
            final_danger_score
        )


        # --------------------------------------------------------
        # FINAL 20 / 80 DECISION
        # --------------------------------------------------------

        if (
            final_danger_score
            >= DANGER_MIN
        ):

            status_label = (
                "DANGEROUS"
            )

            redirect_target = (
                "blocked.html"
            )


            save_to_blocklist(
                target_url,
                final_danger_score
            )


        elif (
            final_danger_score
            > SAFE_MAX
        ):

            status_label = (
                "WARNING"
            )

            redirect_target = (
                "warning.html"
            )


        else:

            status_label = (
                "SAFE"
            )

            redirect_target = (
                None
            )


        print(
            "[FINAL STATUS]",
            status_label
        )

        print("=" * 70)


        # --------------------------------------------------------
        # RETURN RESPONSE
        # --------------------------------------------------------

        return jsonify({

            "url":
                target_url,

            "ml_danger_score":
                round(
                    ml_danger_score,
                    2
                ),

            "danger_score":
                final_danger_score,

            "safe_score":
                round(
                    final_safe_score,
                    2
                ),

            "domain_safe_score":
                domain_safe_score,

            "trust_status":
                trust_status,

            "status":
                status_label,

            "redirect":
                redirect_target
        })


    except Exception as error:

        print("\n")
        print("=" * 70)

        print(
            "PREDICTION ERROR"
        )

        print(
            "Type:",
            type(error).__name__
        )

        print(
            "Message:",
            str(error)
        )

        traceback.print_exc()

        print("=" * 70)


        return jsonify({

            "error":
                str(error),

            "error_type":
                type(error).__name__

        }), 500


# ================================================================
# 18. START FLASK
# ================================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 70)
    print("AI PHISHING SHIELD")
    print("=" * 70)

    print(
        "Model file:",
        "FINAL_HARD_RETRAINED_PHISHING_MODEL.pkl"
    )

    print(
        "Actual model type:",
        type(model)
    )

    print(
        "Features:",
        len(
            FEATURE_NAMES
        )
    )

    print(
        f"SAFE: <= {SAFE_MAX}%"
    )

    print(
        f"WARNING: > {SAFE_MAX}% and < {DANGER_MIN}%"
    )

    print(
        f"DANGEROUS: >= {DANGER_MIN}%"
    )

    print("=" * 70)


    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )
