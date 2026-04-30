from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import os
import pandas as pd
import matplotlib
matplotlib.use('Agg') 
import joblib
from django.core.paginator import Paginator
from .utils.llm_utils import (
    generate_threat_explanation,
    generate_batch_explanation   
)

#module try catch that fetches the model once its been tested on the user data
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(CURRENT_DIR, 'RForestModal.pkl')
try:
    mod = joblib.load(MODEL_PATH) #this is the model thats used to test 
    print("SUCCESSFULY loaded Random Forest Model into memory!")
except:
    mod=None #if the file is not found in the same directory as this view file it will retrieve None value
    print("UNSUCCESSFUL load of Random Forest Model into memory!")


class ModalSingle(APIView):
    #post endpoint that gets called when a single sample user is tested
    #the values/scores, accruacy and risk indicators are returned as a response back to the frontend
    def post(self,request,format=None):
        try:
            data = request.data #take in the json object with the user data or row in the case of the our format
            df = pd.DataFrame([data]) #turn into a dataframe
            df = df.drop(columns=['index','is_malicious'], errors='ignore') #drop unneeded fields 'index' and 'is_malicious'
            df_encoded = pd.get_dummies(df)
            if mod and hasattr(mod,"feature_names_in_"):
                model_features=list(mod.feature_names_in_)
                for col in model_features:
                    if col not in df_encoded.columns:
                        df_encoded[col]=0
                df_encoded=df_encoded[model_features]

            if mod:
                pred = int(mod.predict(df_encoded)[0]) #retrieve the first value in the after values are dripped with is the id
                conf=float(max(mod.predict_proba(df_encoded)[0]))
            else:
                #default confidence values are given if mod doesnt contain anything
                pc= 1 if data.get('late_exit_flag')==1 else 0
                conf = 0.75
            

            #this indicates if the values are malicious or normal based on the predicted confidence
            pred_l = 'Malicious' if pred == 1 else 'Normal'            
            risk_indicators=[]
            if data.get('total_files_burned', 0) > 0:
                risk_indicators.append(f"Burned {data['total_files_burned']} files to USB/Disk")
            if data.get('entry_during_weekend') == 1:
                risk_indicators.append("Campus entry detected during the weekend")
            if data.get('late_exit_flag') == 1:
                risk_indicators.append("Flagged for late exit")
            if not risk_indicators:
                risk_indicators.append(
                    "No abnormal behavior detected"
                    if pred_l == "Normal"
                    else "Potential anomaly detected"
                )

            profile = {
                "department": data.get("categ_Engineering Department") and "Engineering" or "Other",
                "seniority": data.get("employee_seniority_years", 0)
            }

            explanation  = generate_threat_explanation(profile,pred_l,conf,risk_indicators)

            # return the exact structure required in frontend integration
            return Response({
                    "status": "success",
                    "data": {
                        "prediction": pred_l,
                        "confidence": round(conf, 4),
                        "risk_indicators": risk_indicators,
                        "explanation":explanation 
                    }
                }, status=status.HTTP_200_OK)
        except Exception as e:
            #default excetion thats caught in case of errors
            print(f"Server Error: {e}")
            return Response({'status':'Internal error',
                             'message':str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        return Response({'message':'Modal single'},status=status.HTTP_200_OK)

class ModalCSV(APIView):
    def post(self, request, format=None):
        file_data = request.FILES.get('csvFile')

        if not file_data:
            return Response({'error': 'File data not found'}, status=400)

        try:
            df_raw = pd.read_csv(file_data).drop_duplicates().dropna()
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
            x_pred = df_encoded.drop(columns=['is_malicious', 'index'], errors='ignore')
            preds = mod.predict(x_pred)
            probs = mod.predict_proba(x_pred)

            results = []
            threats_found = 0
            high_risk = 0
            medium_risk = 0
            MAX_LLM_ROWS = 5
            llm_count = 0

            for i in range(len(x_pred)):
                pred_val = int(preds[i])
                conf = float(max(probs[i]))

                label = 'Malicious' if pred_val == 1 else 'Normal'
                if label == 'Malicious':
                    threats_found += 1
                    if conf >= 0.85:
                        high_risk += 1
                    else:
                        medium_risk += 1

                row = x_pred.iloc[i]

                risk_indicators = []
                if row.get('total_files_burned', 0) > 0:
                    risk_indicators.append("USB activity")
                if row.get('entry_during_weekend') == 1:
                    risk_indicators.append("Weekend access")
                if row.get('late_exit_flag') == 1:
                    risk_indicators.append("Late exit")

                if not risk_indicators:
                    risk_indicators.append(
                        "Normal behavior" if label == "Normal" else "Anomaly detected"
                    )
             

                result_row = {
                        "row_index": int(i),
                        "prediction": label,
                        "confidence": round(conf, 4),
                        "risk_indicators": risk_indicators,
                        "explanation": None  
                }
                if label == "Malicious" and conf >= 0.85 and llm_count < MAX_LLM_ROWS:
                    user_profile = {
                        "department": "Unknown",  # optional improvement later
                        "seniority": row.get("employee_seniority_years", 0)
                    }

                    result_row['explanation']  = generate_threat_explanation(user_profile,label,conf,risk_indicators)
                    llm_count += 1

                results.append(result_row)

            filter_type = request.query_params.get("filter", "all")

            if filter_type == "malicious":
                results = [r for r in results if r["prediction"] == "Malicious"]
            elif filter_type == "normal":
                results = [r for r in results if r["prediction"] == "Normal"]

            sort_by = request.query_params.get("sort_by", "confidence") #if theres no value in the request the return dummy value
            order = request.query_params.get("order", "desc")

            reverse = True if order == "desc" else False
            results.sort(key=lambda x: x.get(sort_by, 0), reverse=reverse)
            #pagination to best handle request on frontend of the prototype 
            page = int(request.query_params.get("page", 1))
            page_size = int(request.query_params.get("page_size", 10))

            paginator = Paginator(results, page_size)
            page_obj = paginator.get_page(page)

            global_scores = pd.Series(
                mod.feature_importances_,
                index=x_pred.columns
            ).nlargest(3)

            insights = [
                {"feature": str(k), "importance": float(v)}
                for k, v in global_scores.items()
            ]
            summary={
                    "total_scanned": len(df_raw),
                    "threats_found": threats_found,
                    "high_risk": high_risk,
                    "medium_risk": medium_risk,
                    "threat_percentage": round((threats_found / len(results)) * 100, 1) if results else 0
                }
            explanation = generate_batch_explanation(summary, insights)

            return Response({
                "status": "success",
                "summary":summary,
                "feature_insights": insights,
                "batch_explanation":explanation,
                "data": list(page_obj),
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": paginator.count,
                    "total_pages": paginator.num_pages
                }
            })

        except Exception as e:
            return Response({'error': str(e)}, status=500)