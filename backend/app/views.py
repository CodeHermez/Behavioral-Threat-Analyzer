from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema,OpenApiExample, OpenApiParameter
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
import uuid
ANALYSIS_STORE={}

#module try catch that fetches the model once its been tested on the user data
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(CURRENT_DIR, 'RForestModal.pkl')
try:
    mod = joblib.load(MODEL_PATH) #this is the model thats used to test 
    print("SUCCESSFULY loaded Random Forest Model into memory!")
except:
    mod=None #if the file is not found in the same directory as this view file it will retrieve None value
    print("UNSUCCESSFUL load of Random Forest Model into memory!")


class ModalSampleView(APIView):
    @extend_schema(
        summary="Analyze a sample employee profile",
        description="""
        Performs machine learning inference on a sample employee record.

        Returns:
        - Prediction (Malicious / Normal)
        - Confidence score
        - Behavioural risk indicators
        - AI-generated explanation (LLM)

        Used for deep inspection of individual cases.
        """,
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "employee_seniority_years": {"type": "number"},
                    "employee_classification": {"type": "number"},
                    "total_files_burned": {"type": "number"},
                    "entry_during_weekend": {"type": "number"},
                    "late_exit_flag": {"type": "number"}
                }
            }
        },
        responses={
            200: {
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "data": {
                        "type": "object",
                        "properties": {
                            "prediction": {"type": "string"},
                            "confidence": {"type": "number"},
                            "risk_indicators": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "llm_explanation": {"type": "string"}
                        }
                    }
                }
            }
        },
        examples=[
            OpenApiExample(
                'Successful Response',
                value={
                    "status": "success",
                    "data": {
                        "prediction": "Malicious",
                        "confidence": 0.83,
                        "risk_indicators": [
                            "USB activity",
                            "Weekend access"
                        ],
                        "llm_explanation": "This activity shows unusual off-hours behaviour..."
                    }
                }
            )
        ]
    )
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

            llm_explanation  = generate_threat_explanation(profile,pred_l,conf,risk_indicators)

            # return the exact structure required in frontend integration
            return Response({
                    "status": "success",
                    "data": {
                        "prediction": pred_l,
                        "confidence": round(conf, 4),
                        "risk_indicators": risk_indicators,
                        "llm_explanation":llm_explanation 
                    }
                }, status=status.HTTP_200_OK)
        except Exception as e:
            #default excetion thats caught in case of errors
            print(f"Server Error: {e}")
            return Response({'status':'Internal error',
                             'message':str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        return Response({'message':'Modal sample'},status=status.HTTP_200_OK)

class ModalCsvView(APIView):
    @extend_schema(
        summary="Analyze CSV dataset (bulk threat detection)",
        description="""
        Upload a CSV file to perform large-scale behavioural threat analysis.

        Features:
        - Batch prediction using ML model
        - Risk classification per row
        - Aggregated threat summary
        - Feature importance insights
        - AI-generated batch explanation

        Supports:
        - Filtering (malicious / normal)
        - Sorting (confidence / prediction)
        - Pagination

        Performance optimised:
        - AI explanations limited to top high-risk rows
        """,
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "csvFile": {
                        "type": "string",
                        "format": "binary"
                    }
                }
            }
        },
        responses={
            200: {
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "summary": {"type": "object"},
                    "feature_insights": {"type": "array"},
                    "data": {"type": "array"},
                    "pagination": {"type": "object"}
                }
            }
        },
        parameters=[
        OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY),
        OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY),
        OpenApiParameter(name='filter', type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name='sort_by', type=str, location=OpenApiParameter.QUERY),
        OpenApiParameter(name='order', type=str, location=OpenApiParameter.QUERY),
        ],
        examples=[
            OpenApiExample(
                'CSV Analysis Response',
                value={
                    "status": "success",
                    "summary": {
                        "total_scanned": 1000,
                        "threats_found": 74,
                        "high_risk": 20,
                        "medium_risk": 54,
                        "threat_percentage": 7.4
                    },
                    "data": [
                        {
                            "row_index": 1,
                            "prediction": "Malicious",
                            "confidence": 0.87,
                            "risk_indicators": ["USB activity"]
                        }
                    ],
                    "pagination": {
                        "page": 1,
                        "total_pages": 10
                    }
                }
            )
        ]
    )
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
            # MAX_LLM_ROWS = 5
            # llm_count = 0
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
                    "threat_percentage": round((threats_found / len(df_raw)) * 100, 1) if results else 0,
                }
            
            print("start of llm explanation")
            summary['llm_explanation'] = generate_batch_explanation(summary, insights)
            print("end of llm explanation")
            
            tp = fp = fn = tn = 0 #definition of false-positive, true-positive... etc

            for i in range(len(x_pred)):
                actual = int(df_raw.iloc[i]["is_malicious"]) if "is_malicious" in df_raw.columns else None
                predicted = int(preds[i])

                if actual == 1 and predicted == 1:
                    tp += 1
                elif actual == 0 and predicted == 1:
                    fp += 1
                elif actual == 1 and predicted == 0:
                    fn += 1
                elif actual == 0 and predicted == 0:
                    tn += 1

                summary['evaluation']={
                    "true_positives": tp,
                    "false_positives": fp,
                    "false_negatives": fn,
                    "true_negatives": tn,
                    "precision": round(tp / (tp + fp), 2) if (tp + fp) else 0,
                    "recall": round(tp / (tp + fn), 2) if (tp + fn) else 0,
                }

            return Response({
                "status": "success",
                "summary":summary,
                "feature_insights": insights,
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
        
class ModalCsvAnalyzeView(APIView):
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

            df_clean = df_raw.drop(columns=[c for c in cols_to_drop if c in df_raw.columns], errors='ignore')

            df_encoded = pd.get_dummies(
                df_clean,
                columns=['employee_department', 'employee_position'],
                prefix='categ'
            )

            x_pred = df_encoded.drop(columns=['is_malicious', 'index'], errors='ignore')

            preds = mod.predict(x_pred)
            probs = mod.predict_proba(x_pred)

            results = []
            threats_found = high_risk = medium_risk = 0

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
                    risk_indicators.append("Normal behavior" if label == "Normal" else "Anomaly detected")

                results.append({
                    "row_index": i,
                    "prediction": label,
                    "confidence": round(conf, 4),
                    "risk_indicators": risk_indicators
                })

            # summary
            summary = {
                "total_scanned": len(df_raw),
                "threats_found": threats_found,
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "threat_percentage": round((threats_found / len(df_raw)) * 100, 1)
            }

            # feature importance
            global_scores = pd.Series(
                mod.feature_importances_,
                index=x_pred.columns
            ).nlargest(3)

            insights = [{"feature": str(k), "importance": float(v)} for k, v in global_scores.items()]

            summary['llm_explanation'] = generate_batch_explanation(summary, insights)

            # evaluation
            tp = fp = fn = tn = 0
            for i in range(len(x_pred)):
                actual = int(df_raw.iloc[i]["is_malicious"]) if "is_malicious" in df_raw.columns else None
                predicted = int(preds[i])

                if actual == 1 and predicted == 1: tp += 1
                elif actual == 0 and predicted == 1: fp += 1
                elif actual == 1 and predicted == 0: fn += 1
                elif actual == 0 and predicted == 0: tn += 1

            summary["evaluation"] = {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": tn,
                "precision": round(tp / (tp + fp), 2) if (tp + fp) else 0,
                "recall": round(tp / (tp + fn), 2) if (tp + fn) else 0,
            }

            # 🔥 store results
            analysis_id = str(uuid.uuid4())
            ANALYSIS_STORE[analysis_id] = results

            # return first page only
            paginator = Paginator(results, 10)
            page_obj = paginator.get_page(1)

            return Response({
                "analysis_id": analysis_id,
                "summary": summary,
                "feature_insights": insights,
                "data": list(page_obj),
                "pagination": {
                    "page": 1,
                    "total_pages": paginator.num_pages
                }
            })

        except Exception as e:
            return Response({'error': str(e)}, status=500)

class ModalCsvResultsView(APIView):
    def get(self, request):
        analysis_id = request.query_params.get("analysis_id")

        if analysis_id not in ANALYSIS_STORE:
            return Response({"error": "Invalid analysis_id"}, status=400)

        results = ANALYSIS_STORE[analysis_id]

        # filtering
        filter_type = request.query_params.get("filter", "all")
        if filter_type == "malicious":
            results = [r for r in results if r["prediction"] == "Malicious"]
        elif filter_type == "normal":
            results = [r for r in results if r["prediction"] == "Normal"]

        # sorting
        sort_by = request.query_params.get("sort_by", "confidence")
        order = request.query_params.get("order", "desc")
        reverse = order == "desc"

        results.sort(key=lambda x: x.get(sort_by, 0), reverse=reverse)

        # pagination
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 10))

        paginator = Paginator(results, page_size)
        page_obj = paginator.get_page(page)

        return Response({
            "data": list(page_obj),
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": paginator.count,
                "total_pages": paginator.num_pages
            }
        })