from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    g
)

import os
import sqlite3
import json
from functools import wraps
from datetime import datetime

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from scanner import scan_project, scan_pasted_code
from security_seal import create_security_passport
from blockchain_proof import create_blockchain_proof


app = Flask(__name__)

# =========================================================
# APP CONFIG
# =========================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "securecode-ai-demo-secret-key"
)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"zip"}

DATABASE = "securecode.db"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# =========================================================
# DATABASE
# =========================================================

def get_db():

    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")

    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():

    connection = get_db()

    cursor = connection.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            email TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            created_at TEXT NOT NULL

        )
    """)

    # Audit history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audits (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            project_name TEXT NOT NULL,

            score INTEGER NOT NULL,

            risk_level TEXT NOT NULL,

            files_scanned INTEGER DEFAULT 0,

            findings_count INTEGER DEFAULT 0,

            high_count INTEGER DEFAULT 0,

            medium_count INTEGER DEFAULT 0,

            low_count INTEGER DEFAULT 0,

            report_hash TEXT,

            passport_id TEXT,

            blockchain_status TEXT,

            report_json TEXT NOT NULL,

            created_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
                REFERENCES users(id) ON DELETE CASCADE

        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_audits_user_id ON audits(user_id);
    """)

    connection.commit()


with app.app_context():
    init_db()


# =========================================================
# LOGIN REQUIRED DECORATOR
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login to access your dashboard.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return wrapper


# =========================================================
# BASIC FUNCTIONS
# =========================================================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def calculate_score(findings):

    score = 100

    for finding in findings:

        severity = finding.get(
            "ml_severity",
            finding.get("severity", "Low")
        )

        if severity == "High":
            score -= 25

        elif severity == "Medium":
            score -= 15

        elif severity == "Low":
            score -= 5

    return max(score, 0)


def get_risk_level(score):

    if score >= 80:
        return "LOW"

    if score >= 50:
        return "MEDIUM"

    if score >= 25:
        return "HIGH"

    return "CRITICAL"


def build_clusters(findings):

    clusters = {}

    for finding in findings:

        cluster = finding.get(
            "cluster",
            "Other"
        )

        clusters[cluster] = (
            clusters.get(cluster, 0) + 1
        )

    return clusters


def build_ml_summary(findings):

    if not findings:

        return {
            "average_confidence": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

    confidence = [

        finding.get(
            "ml_confidence",
            0
        )

        for finding in findings

    ]

    return {

        "average_confidence":
            round(
                sum(confidence) /
                len(confidence)
            ),

        "high":
            sum(
                1
                for f in findings
                if f.get("ml_severity") == "High"
            ),

        "medium":
            sum(
                1
                for f in findings
                if f.get("ml_severity") == "Medium"
            ),

        "low":
            sum(
                1
                for f in findings
                if f.get("ml_severity") == "Low"
            )

    }


# =========================================================
# BUILD SCAN RESULT
# =========================================================

def prepare_results(
    filename,
    files_scanned,
    findings
):

    score = calculate_score(findings)

    risk = get_risk_level(score)

    passport = create_security_passport(

        filename,
        score,
        findings,
        files_scanned

    )

    blockchain = create_blockchain_proof(
        passport
    )

    return {

        "filename": filename,

        "files_scanned":
            files_scanned,

        "findings":
            findings,

        "score":
            score,

        "risk_level":
            risk,

        "clusters":
            build_clusters(findings),

        "ml":
            build_ml_summary(findings),

        "passport":
            passport,

        "blockchain":
            blockchain

    }


# =========================================================
# SAVE AUDIT TO USER HISTORY
# =========================================================

def save_audit(user_id, data):

    findings = data.get(
        "findings",
        []
    )

    high_count = sum(
        1
        for finding in findings
        if finding.get(
            "ml_severity",
            finding.get("severity")
        ) == "High"
    )

    medium_count = sum(
        1
        for finding in findings
        if finding.get(
            "ml_severity",
            finding.get("severity")
        ) == "Medium"
    )

    low_count = sum(
        1
        for finding in findings
        if finding.get(
            "ml_severity",
            finding.get("severity")
        ) == "Low"
    )

    passport = data.get(
        "passport",
        {}
    )

    blockchain = data.get(
        "blockchain",
        {}
    )

    report_hash = passport.get(
        "report_hash",
        ""
    )

    passport_id = passport.get(
        "passport_id",
        ""
    )

    blockchain_status = blockchain.get(
        "status",
        "READY_FOR_BLOCKCHAIN"
    )

    connection = get_db()

    connection.execute(
        """
        INSERT INTO audits (

            user_id,
            project_name,
            score,
            risk_level,
            files_scanned,
            findings_count,
            high_count,
            medium_count,
            low_count,
            report_hash,
            passport_id,
            blockchain_status,
            report_json,
            created_at

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (

            user_id,

            data.get(
                "filename",
                "Unknown Project"
            ),

            data.get(
                "score",
                0
            ),

            data.get(
                "risk_level",
                "UNKNOWN"
            ),

            data.get(
                "files_scanned",
                0
            ),

            len(findings),

            high_count,

            medium_count,

            low_count,

            report_hash,

            passport_id,

            blockchain_status,

            json.dumps(
                data
            ),

            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        )

    )

    connection.commit()


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not name or not email or not password:

            flash(
                "Please fill all fields.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "error"
            )

            return render_template(
                "register.html"
            )

        connection = get_db()

        existing_user = connection.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if existing_user:

            flash(
                "An account with this email already exists.",
                "error"
            )

            return render_template(
                "register.html"
            )

        password_hash = generate_password_hash(
            password
        )

        connection.execute(
            """
            INSERT INTO users (
                name,
                email,
                password_hash,
                created_at
            )

            VALUES (?, ?, ?, ?)
            """,

            (
                name,
                email,
                password_hash,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        connection.commit()

        flash(
            "Account created successfully. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if (
            user
            and check_password_hash(
                user["password_hash"],
                password
            )
        ):

            session.clear()

            session["user_id"] = user["id"]

            session["user_name"] = user["name"]

            session["user_email"] = user["email"]

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid email or password.",
            "error"
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user_id = session["user_id"]

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    audits = connection.execute(
        """
        SELECT *
        FROM audits

        WHERE user_id = ?

        ORDER BY id DESC
        """,
        (user_id,)
    ).fetchall()

    stats = connection.execute(
        """
        SELECT

            COUNT(*) AS total_audits,

            COALESCE(
                ROUND(AVG(score)),
                0
            ) AS average_score,

            COALESCE(
                SUM(
                    CASE
                        WHEN risk_level IN ('HIGH', 'CRITICAL')
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS high_risk_audits

        FROM audits

        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()

    return render_template(
        "dashboard.html",

        user=user,

        audits=audits,

        stats=stats
    )


# =========================================================
# VIEW PREVIOUS AUDIT
# =========================================================

@app.route(
    "/history/<int:audit_id>"
)
@login_required
def view_history(audit_id):

    connection = get_db()

    audit_record = connection.execute(
        """
        SELECT *
        FROM audits

        WHERE id = ?
        AND user_id = ?
        """,

        (
            audit_id,
            session["user_id"]
        )
    ).fetchone()

    if not audit_record:

        return render_template(
            "page.html",
            page="error",
            error="Audit report not found."
        )

    try:

        data = json.loads(
            audit_record["report_json"]
        )

    except Exception:

        return render_template(
            "page.html",
            page="error",
            error="Unable to load saved audit report."
        )

    return render_template(

        "page.html",

        page="results",

        data=data,

        history_view=True

    )


# =========================================================
# INFORMATION PAGES
# =========================================================

@app.route("/audit")
def audit():

    return render_template(
        "page.html",
        page="audit"
    )


@app.route("/ai-engine")
def ai_engine():

    return render_template(
        "page.html",
        page="ai"
    )


@app.route("/ml")
def ml():

    return render_template(
        "page.html",
        page="ml"
    )


@app.route("/clustering")
def clustering():

    return render_template(
        "page.html",
        page="clustering"
    )


@app.route("/privacy")
def privacy():

    return render_template(
        "page.html",
        page="privacy"
    )


@app.route("/blockchain")
def blockchain():

    return render_template(
        "page.html",
        page="blockchain"
    )


@app.route("/passport")
def passport():

    return render_template(
        "page.html",
        page="passport"
    )


@app.route("/reports")
def reports():

    return render_template(
        "page.html",
        page="reports"
    )


@app.route("/about")
def about():

    return render_template(
        "page.html",
        page="about"
    )


# =========================================================
# ZIP SCAN
# =========================================================

@app.route(
    "/upload",
    methods=["POST"]
)
@login_required
def upload_file():

    try:

        if "project" not in request.files:

            return render_template(
                "page.html",
                page="error",
                error="No project file was selected."
            )

        file = request.files["project"]

        if not file.filename:

            return render_template(
                "page.html",
                page="error",
                error="Please select a ZIP file."
            )

        if not allowed_file(
            file.filename
        ):

            return render_template(
                "page.html",
                page="error",
                error="Only ZIP files are supported."
            )

        filename = secure_filename(
            file.filename
        )

        filepath = os.path.join(

            app.config[
                "UPLOAD_FOLDER"
            ],

            filename

        )

        file.save(filepath)

        result = scan_project(
            filepath
        )

        try:

            os.remove(filepath)

        except OSError:

            pass

        if result.get("status") != "success":

            return render_template(

                "page.html",

                page="error",

                error=result.get(
                    "error",
                    "Security scanner failed."
                )

            )

        data = prepare_results(

            filename,

            result.get(
                "files_scanned",
                0
            ),

            result.get(
                "findings",
                []
            )

        )

        # SAVE AUDIT HISTORY
        save_audit(
            session["user_id"],
            data
        )

        return render_template(

            "page.html",

            page="results",

            data=data

        )

    except Exception as e:

        return render_template(

            "page.html",

            page="error",

            error=str(e)

        )


# =========================================================
# PASTED CODE SCAN
# =========================================================

@app.route(
    "/scan-code",
    methods=["POST"]
)
@login_required
def scan_code():

    try:

        code = request.form.get(
            "code",
            ""
        )

        language = request.form.get(
            "language",
            "Unknown"
        )

        if not code.strip():

            return render_template(

                "page.html",

                page="error",

                error="Please paste source code before scanning."

            )

        result = scan_pasted_code(

            code,

            language

        )

        if result.get("status") != "success":

            return render_template(

                "page.html",

                page="error",

                error=result.get(
                    "error",
                    "Code scanner failed."
                )

            )

        filename = (
            "Pasted "
            + language
            + " Code"
        )

        data = prepare_results(

            filename,

            result.get(
                "files_scanned",
                1
            ),

            result.get(
                "findings",
                []
            )

        )

        # SAVE AUDIT HISTORY
        save_audit(
            session["user_id"],
            data
        )

        return render_template(

            "page.html",

            page="results",

            data=data

        )

    except Exception as e:

        return render_template(

            "page.html",

            page="error",

            error=str(e)

        )


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )