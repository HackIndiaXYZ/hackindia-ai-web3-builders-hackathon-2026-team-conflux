import os
import re
import zipfile
import tempfile
import shutil

from ml_classifier import analyze_findings


# =========================================================
# SUPPORTED FILE TYPES
# =========================================================

ALLOWED_EXTENSIONS = {
    ".html", ".htm", ".css", ".js", ".jsx",
    ".ts", ".tsx", ".php", ".py", ".java",
    ".c", ".cpp", ".h", ".json", ".xml",
    ".sql", ".env", ".txt"
}


# =========================================================
# SAFE ZIP PATH CHECK
# =========================================================

def is_safe_path(base_path, target_path):
    base_path = os.path.abspath(base_path)
    target_path = os.path.abspath(target_path)

    return os.path.commonpath(
        [base_path, target_path]
    ) == base_path


def extract_zip_safely(zip_path, extract_to):

    with zipfile.ZipFile(zip_path, "r") as zip_file:

        for member in zip_file.infolist():

            target_path = os.path.join(
                extract_to,
                member.filename
            )

            if not is_safe_path(
                extract_to,
                target_path
            ):
                raise ValueError(
                    "Unsafe file path detected inside ZIP."
                )

        zip_file.extractall(extract_to)


# =========================================================
# FINDING CREATOR
# =========================================================

def add_finding(
    findings,
    finding_type,
    severity,
    file_path,
    message,
    recommendation,
    impact="",
    explanation=""
):

    findings.append({
        "type": finding_type,
        "severity": severity,
        "file": file_path,
        "message": message,
        "recommendation": recommendation,
        "impact": impact,
        "explanation": explanation
    })


# =========================================================
# STATIC SECURITY SCANNER
# =========================================================

def scan_content(content, file_path="Pasted Code"):

    findings = []

    extension = os.path.splitext(file_path)[1].lower()

    # =====================================================
    # 1. HARDCODED PASSWORD
    # =====================================================

    password_pattern = re.compile(
        r"(password|passwd|pwd)"
        r"\s*[:=]\s*[\"'][^\"']+[\"']",
        re.IGNORECASE
    )

    if password_pattern.search(content):

        add_finding(
            findings,
            "Hardcoded Password",
            "High",
            file_path,
            "CodeSecure detected a value that appears to be a password stored directly inside the source code.",
            "Remove the password from the source code and store it securely using environment variables or a secret-management system.",
            "If this password is real, someone who gains access to the source code may be able to use it to access an application, database, or other service.",
            "Passwords should generally never be permanently embedded inside application source code."
        )


    # =====================================================
    # 2. POSSIBLE API KEY / SECRET
    # =====================================================

    api_pattern = re.compile(
        r"(api[\-_]?key|secret[\-_]?key)"
        r"\s*[:=]\s*[\"'][^\"']+[\"']",
        re.IGNORECASE
    )

    if api_pattern.search(content):

        add_finding(
            findings,
            "Possible API Key / Secret",
            "High",
            file_path,
            "CodeSecure detected a value that appears to be an API key or secret embedded directly inside the source code.",
            "Remove the credential from the source code. If it is real, revoke or rotate it and store the replacement securely using environment variables or a secret-management system.",
            "An exposed API key may allow unauthorized use of connected services. Depending on its permissions, this could result in data exposure, service abuse, or unexpected costs.",
            "Credentials inside source code can accidentally become public through GitHub repositories, website deployments, backups, or shared project files."
        )


    # =====================================================
    # 3. JAVASCRIPT eval()
    # =====================================================

    if extension in {
        ".js", ".jsx", ".ts", ".tsx",
        ".html", ".htm"
    }:

        if re.search(
            r"\beval\s*\(",
            content,
            re.IGNORECASE
        ):

            add_finding(
                findings,
                "Dangerous JavaScript Function",
                "Medium",
                file_path,
                "The eval() function was detected in the analyzed code.",
                "Avoid eval() whenever possible. Use safer alternatives that do not execute dynamically supplied code.",
                "If untrusted input reaches eval(), an attacker may potentially influence what code is executed in the application.",
                "eval() converts a string into executable JavaScript, which makes it difficult to control and safely validate dynamic input."
            )


    # =====================================================
    # 4. INNERHTML / POSSIBLE XSS
    # =====================================================

    if extension in {
        ".js", ".jsx", ".ts", ".tsx",
        ".html", ".htm"
    }:

        if re.search(
            r"\.innerHTML\s*=",
            content,
            re.IGNORECASE
        ):

            add_finding(
                findings,
                "Potential XSS Risk",
                "Medium",
                file_path,
                "Direct assignment to innerHTML was detected.",
                "When inserting untrusted text, prefer safer DOM APIs such as textContent. If HTML must be inserted, sanitize the content appropriately.",
                "If attacker-controlled content is inserted into innerHTML without proper sanitization, malicious browser-side content may potentially be executed.",
                "Using innerHTML is not automatically a vulnerability, but it becomes risky when the assigned value contains untrusted user-controlled data."
            )


    # =====================================================
    # 5. POSSIBLE SQL INJECTION
    # =====================================================

    if extension in {
        ".php", ".py", ".java",
        ".js", ".jsx", ".ts", ".tsx",
        ".sql"
    }:

        sql_pattern = re.compile(
            r"(SELECT|INSERT|UPDATE|DELETE)"
            r".*(\+|\$\{|%s)",
            re.IGNORECASE
        )

        if sql_pattern.search(content):

            add_finding(
                findings,
                "Possible SQL Injection Risk",
                "High",
                file_path,
                "CodeSecure detected a pattern that may indicate SQL queries are being constructed using dynamically combined values.",
                "Use parameterized queries or prepared statements instead of directly combining user-controlled values with SQL statements.",
                "Unsafe SQL construction can potentially allow manipulated input to change the intended database query.",
                "This is a pattern-based detection. CodeSecure cannot determine from this check alone whether the input is actually attacker-controlled."
            )


    # =====================================================
    # 6. HTTP INSTEAD OF HTTPS
    # =====================================================

    http_pattern = re.compile(
        r"https?://[^\s\"'<>]+",
        re.IGNORECASE
    )

    http_matches = http_pattern.findall(content)

    insecure_http_found = any(
        url.lower().startswith("http://")
        for url in http_matches
    )

    if insecure_http_found:

        add_finding(
            findings,
            "Insecure HTTP Reference",
            "Low",
            file_path,
            "An HTTP URL was detected instead of HTTPS.",
            "Use HTTPS wherever possible for website communication and external resources.",
            "HTTP does not provide the same transport protection as HTTPS, which may expose transmitted information to interception or manipulation.",
            "Some HTTP references may be intentional or harmless, so this finding should be manually reviewed."
        )


    # =====================================================
    # 7. DEBUG MODE
    # =====================================================

    if extension == ".py":

        if re.search(
            r"debug\s*=\s*True",
            content,
            re.IGNORECASE
        ):

            add_finding(
                findings,
                "Debug Mode Enabled",
                "Medium",
                file_path,
                "Debug mode appears to be enabled in the analyzed Python code.",
                "Disable debug mode before deploying the website to production.",
                "Debug configurations can sometimes expose detailed error information, application paths, configuration details, or other information that should not be visible to visitors.",
                "Debug mode is useful during development but should normally be disabled in a production environment."
            )


    # =====================================================
    # 8. ML CLASSIFICATION + CLUSTERING
    # =====================================================

    if findings:

        ml_result = analyze_findings(findings)

        return ml_result["findings"]

    return findings


# =========================================================
# SCAN SINGLE FILE
# =========================================================

def scan_file(file_path):

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            content = file.read()

    except Exception:

        return []

    return scan_content(
        content,
        file_path
    )


# =========================================================
# SCAN PASTED CODE
# =========================================================

def scan_pasted_code(
    code,
    language="Unknown"
):

    if not code or not code.strip():

        return {
            "files_scanned": 0,
            "findings": [],
            "status": "error",
            "error": "No code was provided."
        }

    findings = scan_content(
        code,
        f"Pasted Code ({language})"
    )

    return {
        "files_scanned": 1,
        "findings": findings,
        "status": "success"
    }


# =========================================================
# SCAN COMPLETE ZIP PROJECT
# =========================================================

def scan_project(zip_path):

    temp_directory = tempfile.mkdtemp(
        prefix="codesecure_"
    )

    findings = []
    files_scanned = 0

    try:

        # -------------------------------------------------
        # SAFE EXTRACTION
        # -------------------------------------------------

        extract_zip_safely(
            zip_path,
            temp_directory
        )


        # -------------------------------------------------
        # WALK THROUGH PROJECT
        # -------------------------------------------------

        for root, directories, files in os.walk(
            temp_directory
        ):

            for filename in files:

                extension = os.path.splitext(
                    filename
                )[1].lower()

                if extension not in ALLOWED_EXTENSIONS:
                    continue


                file_path = os.path.join(
                    root,
                    filename
                )

                files_scanned += 1


                file_findings = scan_file(
                    file_path
                )


                findings.extend(
                    file_findings
                )


        # -------------------------------------------------
        # RETURN RESULT
        # -------------------------------------------------

        return {
            "files_scanned": files_scanned,
            "findings": findings,
            "status": "success"
        }


    except Exception as error:

        return {
            "files_scanned": files_scanned,
            "findings": [],
            "status": "error",
            "error": str(error)
        }


    finally:

        # -------------------------------------------------
        # DELETE TEMPORARY EXTRACTED PROJECT
        # -------------------------------------------------

        shutil.rmtree(
            temp_directory,
            ignore_errors=True
        )