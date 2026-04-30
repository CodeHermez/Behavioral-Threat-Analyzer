# your_app/llm_utils.py
import os
import google.generativeai as genai

# Configure the API key
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

# Initialize the model (Gemini 1.5 Flash is incredibly fast and cheap for this)
model = genai.GenerativeModel('gemini-3')

from collections import Counter

def build_batch_summary(results):
    total = len(results)
    malicious = [r for r in results if r["prediction"] == "Malicious"]

    feature_counter = Counter()

    for row in malicious:
        for risk in row["risk_indicators"]:
            feature_counter[risk] += 1

    top_patterns = feature_counter.most_common(5)

    return {
        "total_records": total,
        "malicious_count": len(malicious),
        "malicious_percentage": (len(malicious) / total) * 100 if total else 0,
        "top_patterns": top_patterns
    }

def build_row_explanation_payload(row, prediction, confidence):
    factors = build_row_explanation_data(row)

    return {
        "prediction": prediction,
        "confidence": confidence,
        "risk_level": get_risk_level(confidence),
        "factors": factors,
        "top_factor": factors[0] if factors else None
    }

def build_row_explanation_data(row):
    factors = []

    if row["num_printed_pages_off_hours"] > 20:
        factors.append({
            "name": "High off-hours printing",
            "impact": 0.3,
            "description": "Unusual activity outside normal working hours"
        })

    if row["entry_during_weekend"] == 1:
        factors.append({
            "name": "Weekend access",
            "impact": 0.25,
            "description": "Access during non-working days"
        })

    if row["total_files_burned"] > 10:
        factors.append({
            "name": "USB file transfers",
            "impact": 0.35,
            "description": "Potential data exfiltration via external devices"
        })

    return sorted(factors, key=lambda x: x["impact"], reverse=True)

def generate_threat_explanation(user_profile, prediction, confidence, risk_indicators):
    risk_level = get_risk_level(confidence)

    formatted_indicators = "\n".join(
        [f"- {r['name']} ({r['impact']} impact)" for r in risk_indicators]
    )

    prompt = f"""
    You are a cybersecurity risk analyst explaining model decisions to a non-technical manager.

    The ML model evaluated the following employee:
    - Department: {user_profile.get('department')}
    - Seniority: {user_profile.get('seniority')} years

    Model Output:
    - Prediction: {prediction}
    - Confidence: {confidence * 100:.1f}%
    - Risk Level: {risk_level}

    Key contributing factors:
    {formatted_indicators}

    Base your explanation ONLY on the provided risk indicators.
    Do not introduce new assumptions or external reasoning.

    Write a concise, professional 3 sentence explanation explaining why this activity was flagged and what should be monitored.
    Use simple, non-technical language.
    """

    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"Gemini API Error: {e}")
        return fallback_explanation(prediction, risk_indicators)

#save function that gets initiated when AI model request fails.
def fallback_explanation(prediction, risk_indicators):
    indicators = ", ".join([r["name"] for r in risk_indicators])
    return f"This activity was classified as {prediction} due to the following indicators: {indicators}."

#transalte the risk so that its easily understandable to a manager
def get_risk_level(confidence):
    if confidence >= 0.85:
        return "High Risk"
    elif confidence >= 0.6:
        return "Moderate Risk"
    return "Low Risk"

def risk_distribution(results):
    dist = {"High": 0, "Medium": 0, "Low": 0}

    for r in results:
        level = get_risk_level(r["confidence"])
        dist[level] += 1

    return dist

def build_batch_payload(results):
    summary = build_batch_summary(results)
    distribution = risk_distribution(results)

    return {
        **summary,
        "risk_distribution": distribution
    }

def generate_batch_explanation(batch_data):
    prompt = f"""
    You are a cybersecurity analyst summarizing threat patterns for a non-technical manager.

    Dataset Summary:
    - Total records: {batch_data['total_records']}
    - Malicious cases: {batch_data['malicious_count']}
    - Percentage flagged: {batch_data['malicious_percentage']:.1f}%

    Top risk patterns:
    {batch_data['top_patterns']}

    Risk distribution:
    {batch_data['risk_distribution']}

    Write a short executive summary explaining:
    - What patterns are emerging
    - What the main risks are
    - What should be monitored

    Keep it simple and actionable.
    """

    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except:
        return "Summary unavailable."