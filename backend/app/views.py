from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema,OpenApiExample, OpenApiParameter
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg') 
from sklearn.metrics import confusion_matrix
from django.core.paginator import Paginator
from django.core.cache import cache
from .utils.explainability_utils import (
    generate_explainability_payload
)
from .utils.llm_utils import (
    generate_threat_explanation,
    generate_batch_explanation,
    get_risk_level 
)
from .utils.data_processing_util import(
    build_results_dataframe,
    build_risk_indicators,
    preprocess_dataframe,
    MODEL_FEATURES, 
    ANALYSIS_STORE,
    MODEL)
import uuid
import hashlib
import json

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

    def post(self, request, format=None): 
        try:
            data = request.data
            df = pd.DataFrame([data])
            df = df.drop(
                columns=['index', 'is_malicious'],
                errors='ignore'
            )
            df_encoded = pd.get_dummies(df)
            df_encoded = df_encoded.reindex(
                columns=MODEL_FEATURES,
                fill_value=0
            )
            pred = int(MODEL.predict(df_encoded)[0])
            conf = float(
                np.max(MODEL.predict_proba(df_encoded)[0])
            )

            prediction_label = (
                "Malicious"
                if pred == 1
                else "Normal"
            )

            risk_indicators = []

            if data.get('total_files_burned', 0) > 0:
                risk_indicators.append(
                    "Burned files to USB/Disk"
                )
            if data.get('entry_during_weekend') == 1:
                risk_indicators.append(
                    "Weekend access detected"
                )
            if data.get('late_exit_flag') == 1:
                risk_indicators.append(
                    "Late exit behavior"
                )
            if not risk_indicators:
                risk_indicators.append(
                    "No abnormal behavior detected"
                )

            profile = {
                "department":
                    "Engineering"
                    if data.get("categ_Engineering Department")
                    else "Other",

                "seniority":
                    data.get(
                        "employee_seniority_years",
                        0
                    )
            }

            explainability = generate_explainability_payload(data)
            llm_explanation = generate_threat_explanation(
                profile,
                prediction_label,
                conf,
                risk_indicators
            )

            return Response({
                "status": "success",
                "data": {
                    "prediction": prediction_label,
                    "confidence": round(conf, 4),
                    "risk_indicators": risk_indicators,
                    # "llm_explanation": llm_explanation
                    "rule_based_explanations":explainability["rule_based_explanations"],
                    "feature_contributions":explainability["feature_contributions"],
                    "llm_explanation":llm_explanation
                }
            })

        except Exception as e:

            return Response({
                "status": "error",
                "message": str(e)
            }, status=500)
        
class ModalCsvResultsView(APIView):
    @extend_schema(
        summary="Paginate CSV dataset threat detection results",
        description="""
        Pagination, allows for different results to be produced in the rows of the table produced
        after CSV batch analysis.

        Performance optimised:
        - AI explanations limited to top high-risk rows
        """,
        
        request={
            "multipart/form-data": {
                "type": "string",
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
                    "analysis_id":{"type": "string"},
                    "summary": {"type": "object"},
                    "feature_insights": {"type": "array"},
                    "data": {"type": "array"},
                    "pagination": {"type": "object"}
                }
            }
        },
        parameters=[
        OpenApiParameter(name='analysis_id', type=int, location=OpenApiParameter.QUERY),
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
                    "analysis_id":"0e154789-00d11412",
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
    def get(self, request):
        try:
            analysis_id = request.query_params.get("analysis_id")
            results = cache.get(analysis_id)
            if not results:
                return Response({
                    "error":
                        "Analysis expired or invalid"
                }, status=400)

            results_df = pd.DataFrame(results)
            filter_type = request.query_params.get("filter","all")
            
            if filter_type == "malicious":
                results_df = results_df[results_df["prediction"] == "Malicious"]
            elif filter_type == "normal":
                results_df = results_df[results_df["prediction"] == "Normal"]
            
            sort_by = request.query_params.get("sort_by","confidence")
            order = request.query_params.get("order","desc")
            ascending = order != "desc"
            results_df = results_df.sort_values(by=sort_by,ascending=ascending)
            page = int(request.query_params.get("page", 1))
            page_size = int(request.query_params.get("page_size",10))
            paginator = Paginator(results_df.to_dict("records"),page_size)
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

        except Exception as e:

            return Response({
                "error": str(e)
            }, status=500)
    

#csv analysis
class ModalCsvAnalyzeView(APIView):
    def post(self, request, format=None):
        file = request.FILES.get('csvFile')
        
        if not file:
            return Response({
                'error': 'CSV file not provided'
            }, status=400)
        
        file_b = file.read()
        file_sha=hashlib.md5(file_b).hexdigest()
        cache_analysis = cache.get(file_sha)
        llm_cache_key = f"llm:{file_sha}"
        file.seek(0)
        
        if cache_analysis and llm_cache_key:
            return Response(cache_analysis)


        try:
            df_raw = pd.read_csv(file)
            df_raw = (df_raw.drop_duplicates().dropna().reset_index(drop=True))
            x_pred = preprocess_dataframe(df_raw)
            #setting up raw model prediction layer
            preds = MODEL.predict(x_pred)
            probs = MODEL.predict_proba(x_pred)
            indicators = build_risk_indicators(x_pred)
            # results_df = build_results_dataframe(preds,probs,indicators)
            results = []

            for i in range(len(x_pred)):

                row = x_pred.iloc[i].to_dict()

                pred_val = int(preds[i])

                conf = float(np.max(probs[i]))

                prediction_label = (
                    "Malicious"
                    if pred_val == 1
                    else "Normal")
                #setting up explainability via text rule-based of feature-based generating function
                explainability = (generate_explainability_payload(row))
                human_readable_explanation = (f"This activity was flagged due to: "f"{', '.join(indicators[i])}.")
                results.append({
                    "row_index": int(i),
                    "prediction": prediction_label,
                    "confidence": round(conf, 4),
                    "risk_level":get_risk_level(conf),
                    "risk_indicators":indicators[i],
                    "rule_based_explanations":explainability["rule_based_explanations"],
                    "feature_contributions":explainability["feature_contributions"],
                    "human_readable_explanation": human_readable_explanation
                })
            print('end of loop')
            results_df = pd.DataFrame(results)
            threats_found = int(np.sum(preds == 1))
            confidences = np.max(probs, axis=1)
            high_risk = int(np.sum((preds == 1)&(confidences >= 0.85)))
            medium_risk = int(np.sum((preds == 1)&(confidences < 0.85)))

            summary = {
                "total_scanned": int(len(df_raw)),
                "threats_found": threats_found,
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "threat_percentage": round(
                    (threats_found / len(df_raw)) * 100,
                    1
                )
            }
            feature_scores = pd.Series(MODEL.feature_importances_,index=x_pred.columns).nlargest(3)
            insights = [
                {
                    "feature": str(k),
                    "importance": float(v)
                }
                for k, v in feature_scores.items()
            ]

            if "is_malicious" in df_raw.columns:
                tn, fp, fn, tp = confusion_matrix(df_raw["is_malicious"],preds).ravel()
                summary["evaluation"] = {
                    "true_positives": int(tp),
                    "false_positives": int(fp),
                    "false_negatives": int(fn),
                    "true_negatives": int(tn),
                    "precision":round(tp / (tp + fp),2) if (tp + fp) else 0,
                    "recall":round(tp / (tp + fn),2) if (tp + fn) else 0
                }
            # LLM Intelligence Layer
            top_threat_rows = (results_df[results_df["prediction"] == "Malicious"].sort_values(by="confidence", ascending=False).head(5).to_dict("records"))
            summary["llm_explanation"] = generate_batch_explanation(summary,insights, top_threat_rows)
            cached_llm = cache.get(llm_cache_key)
            analysis_id = str(uuid.uuid4())

            if cached_llm:
                summary["llm_explanation"] = cached_llm
            elif not summary['llm_explanation'] == 'Batch explanation unavailable.':
                llm_explanation = generate_batch_explanation(summary, insights)
                summary["llm_explanation"] = llm_explanation
                cache.set(llm_cache_key,llm_explanation,timeout=86400)
                cache.set(analysis_id,results_df.to_dict("records"),timeout=3600)
                cache.set(file_sha,response,timeout=3600)
            
            page_size = 10
            paginator = Paginator(results_df.to_dict("records"),page_size)
            page_obj = paginator.get_page(1)
            response ={
                "status": "success",
                "analysis_id": analysis_id,
                "summary": summary,
                "feature_insights": insights,
                "data": list(page_obj),
                "pagination": {
                    "page": 1,
                    "page_size": page_size,
                    "total": paginator.count,
                    "total_pages": paginator.num_pages
                }
            }
            cache.set(analysis_id,results_df.to_dict("records"),timeout=3600)
            cache.set(file_sha,response,timeout=3600)
            
            return Response(response)
        except Exception as e:
            return Response({
                "error": str(e)
            }, status=500)