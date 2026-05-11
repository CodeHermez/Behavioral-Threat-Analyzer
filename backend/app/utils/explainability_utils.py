def generate_rule_based_explanations(row):
    explanations = []
    if row.get("total_files_burned", 0) > 10:
        explanations.append("Large number of files copied to external storage")
    elif row.get("total_files_burned", 0) > 0:
        explanations.append("External storage activity detected")
    if row.get("entry_during_weekend", 0) == 1:
        explanations.append("Employee accessed facilities during weekend hours")
    if row.get("late_exit_flag", 0) == 1:
        explanations.append("Late exit behaviour detected outside normal working hours")
    if row.get("employee_seniority_years", 0) < 1:
        explanations.append("Low employee seniority may indicate elevated onboarding risk")
    if not explanations:
        explanations.append("No significant behavioural anomalies detected")
    return explanations

def key_calc(x):
    return abs(x['impact_score'])
def generate_feature_contributions(row):
    # simulated SHAP-style scoring to speedup processing because is normally very slow
    contributions = []
    feature_weights = {
        "total_files_burned": 0.45,
        "entry_during_weekend": 0.30,
        "late_exit_flag": 0.15,
        "employee_seniority_years": -0.10
    }

    for feature, weight in feature_weights.items():
        value = row.get(feature, 0)
        contribution = round(value * weight, 3)
        contributions.append({
            "feature": feature,
            "value": float(value),
            "impact_score": contribution,
            "impact": (
                "High Risk" if contribution > 2 else "Medium Risk" if contribution > 0.5 else "Low Risk"
            )
        })
    contributions = sorted(contributions,key=key_calc,reverse=True)
    return contributions[:3]

def generate_explainability_payload(row):
    return {
        "rule_based_explanations":generate_rule_based_explanations(row),
        "feature_contributions":generate_feature_contributions(row)
    }