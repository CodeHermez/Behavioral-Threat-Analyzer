import numpy as np
import pandas as pd
import os
import joblib
ANALYSIS_STORE={}

#module try catch that fetches the model once its been tested on the user data
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.normpath(os.path.join(CURRENT_DIR, '..','models','RForestModel.pkl'))
try:
    print(MODEL_PATH)
    MODEL = joblib.load(MODEL_PATH) #this is the model thats used to test
    MODEL_FEATURES = list(MODEL.feature_names_in_) 
    print("SUCCESSFULY loaded Random Forest Model into memory!")
except:
    MODEL=None #if the file is not found in the same directory as this view file it will retrieve None value
    MODEL_FEATURES = []
    print("FAILED in loading model")

def build_results_dataframe(preds, probs, indicators):
    #using optimized dataframe instead of standard loops.

    confidences = np.max(probs, axis=1)

    labels = np.where(
        preds == 1,
        "Malicious",
        "Normal"
    )

    return pd.DataFrame({
        "row_index": np.arange(len(preds)),
        "prediction": labels,
        "confidence": np.round(confidences, 4),
        "risk_indicators": indicators
    })

def preprocess_dataframe(df_raw):
    #optimized preprocessing pipeline.

    cols_to_drop = [
        'employee_campus',
        'has_medical_history',
        'employee_origin_country',
        'has_foreign_citizenship',
        'is_contractor'
    ]

    df_clean = df_raw.drop(
        columns=[c for c in cols_to_drop if c in df_raw.columns],
        errors='ignore'
    )

    df_encoded = pd.get_dummies(
        df_clean,
        columns=['employee_department', 'employee_position'],
        prefix='categ'
    )

    x_pred = df_encoded.drop(
        columns=['is_malicious', 'index'],
        errors='ignore'
    )

    #align columns with trained model
    x_pred = x_pred.reindex(
        columns=MODEL_FEATURES,
        fill_value=0
    )

    return x_pred

def build_risk_indicators(df):

    indicators = []

    usb = df["total_files_burned"] > 0
    weekend = df["entry_during_weekend"] == 1
    late = df["late_exit_flag"] == 1

    for i in range(len(df)):

        row_indicators = []

        if usb.iloc[i]:
            row_indicators.append("USB activity")

        if weekend.iloc[i]:
            row_indicators.append("Weekend access")

        if late.iloc[i]:
            row_indicators.append("Late exit")

        if not row_indicators:
            row_indicators.append("Normal behavior")

        indicators.append(row_indicators)

    return indicators