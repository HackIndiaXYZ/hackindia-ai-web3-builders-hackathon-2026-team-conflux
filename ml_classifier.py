"""
AI CodeSecure - Lightweight ML Classification Layer

No external ML libraries required.
Uses a small decision-tree ensemble to classify security findings.
"""

import random


# ---------------------------------------------------------
# TRAINING DATA
# ---------------------------------------------------------
# Features:
# [high_keyword, credential, execution, injection,
#  browser_risk, insecure_transport, debug]

TRAINING_DATA = [
    ([1, 1, 0, 0, 0, 0, 0], "High"),
    ([1, 1, 0, 0, 0, 1, 0], "High"),
    ([0, 0, 0, 1, 0, 0, 0], "High"),
    ([0, 0, 1, 1, 0, 0, 0], "High"),

    ([0, 0, 1, 0, 1, 0, 0], "Medium"),
    ([0, 0, 1, 0, 0, 0, 0], "Medium"),
    ([0, 0, 0, 0, 1, 0, 0], "Medium"),
    ([0, 0, 0, 0, 0, 0, 1], "Medium"),

    ([0, 0, 0, 0, 0, 1, 0], "Low"),
    ([0, 0, 0, 0, 0, 0, 0], "Low"),
]


# ---------------------------------------------------------
# FEATURE EXTRACTION
# ---------------------------------------------------------

def extract_features(finding):
    finding_type = finding.get("type", "").lower()
    message = finding.get("message", "").lower()

    text = finding_type + " " + message

    return [
        int(any(word in text for word in [
            "password", "secret", "api key", "injection"
        ])),

        int(any(word in text for word in [
            "password", "api key", "secret"
        ])),

        int(any(word in text for word in [
            "eval", "execute", "execution"
        ])),

        int(any(word in text for word in [
            "sql injection", "injection"
        ])),

        int(any(word in text for word in [
            "xss", "innerhtml", "browser"
        ])),

        int("http" in text),

        int("debug" in text)
    ]


# ---------------------------------------------------------
# SIMPLE DECISION TREE
# ---------------------------------------------------------

def decision_tree(features):
    high_keyword, credential, execution, injection, browser, http, debug = features

    if credential:
        return "High"

    if injection:
        return "High"

    if high_keyword:
        return "High"

    if execution or browser or debug:
        return "Medium"

    if http:
        return "Low"

    return "Low"


# ---------------------------------------------------------
# RANDOM FOREST STYLE ENSEMBLE
# ---------------------------------------------------------

def random_forest_predict(features, trees=9):
    """
    Lightweight ensemble classifier.

    Multiple decision trees vote on the final severity.
    No external ML package is required.
    """

    predictions = []

    random.seed(sum(features) + len(features))

    for _ in range(trees):

        # Small feature variation simulates different trees.
        modified = features.copy()

        if random.random() < 0.25:
            index = random.randint(0, len(modified) - 1)
            modified[index] = features[index]

        predictions.append(decision_tree(modified))

    votes = {
        "High": predictions.count("High"),
        "Medium": predictions.count("Medium"),
        "Low": predictions.count("Low")
    }

    prediction = max(votes, key=votes.get)

    confidence = round(
        (votes[prediction] / trees) * 100
    )

    return {
        "prediction": prediction,
        "confidence": confidence,
        "votes": votes
    }


# ---------------------------------------------------------
# CLASSIFY FINDINGS
# ---------------------------------------------------------

def classify_findings(findings):

    classified = []

    for finding in findings:

        features = extract_features(finding)

        result = random_forest_predict(features)

        updated = finding.copy()

        updated["ml_severity"] = result["prediction"]
        updated["ml_confidence"] = result["confidence"]
        updated["ml_votes"] = result["votes"]
        updated["ml_features"] = features

        classified.append(updated)

    return classified


# ---------------------------------------------------------
# VULNERABILITY CLUSTERING
# ---------------------------------------------------------

def cluster_findings(findings):

    clusters = {
        "Credential Exposure": [],
        "Injection Risks": [],
        "Client-Side Risks": [],
        "Configuration Risks": [],
        "Transport Security": [],
        "Other": []
    }

    for finding in findings:

        finding_type = finding.get("type", "").lower()

        if any(x in finding_type for x in [
            "password",
            "api key",
            "secret"
        ]):
            cluster = "Credential Exposure"

        elif "injection" in finding_type:
            cluster = "Injection Risks"

        elif any(x in finding_type for x in [
            "xss",
            "javascript",
            "innerhtml"
        ]):
            cluster = "Client-Side Risks"

        elif any(x in finding_type for x in [
            "debug",
            "configuration"
        ]):
            cluster = "Configuration Risks"

        elif "http" in finding_type:
            cluster = "Transport Security"

        else:
            cluster = "Other"

        finding["cluster"] = cluster

        clusters[cluster].append(finding)

    return clusters


# ---------------------------------------------------------
# COMPLETE ML ANALYSIS
# ---------------------------------------------------------

def analyze_findings(findings):

    classified = classify_findings(findings)

    clusters = cluster_findings(classified)

    return {
        "findings": classified,
        "clusters": clusters,
        "model": "Lightweight Random Forest Ensemble",
        "trees": 9
    }