# Threat Detection System Prototype

An AI-driven behavioral analysis dashboard designed to detect, triage, and explain potential insider threats within corporate environments. Traditional rule-based monitoring often fails to catch nuanced, anomalous employee behavior. This system uses a Machine Learning model to analyze organizational logs and classify user behavior as either malicious or normal. 

To bridge the gap between complex AI and security analysts, the system incorporates **Explainable AI (XAI)**, providing human-readable risk indicators and confidence scores to justify its classifications.

## Key Features
* **Behavioral Classification:** Categorizes user activity as either *Malicious Insider Activity* or *Normal / Benign Behaviour*.
* **Explainable AI (XAI):** Outputs specific risk indicators and confidence scores to provide a simple, human-readable explanation of why a profile was flagged.
* **Batch CSV Triage Dashboard:** Upload datasets of employee logs for bulk scanning. The system automatically extracts high-level threat metrics and sorts the most dangerous profiles to the top of the triage roster.
* **Modern UI/UX:** Built with Vue 3 and Vuetify, communicating with a robust Django REST Framework backend.

## Dataset & CSV Structure Requirements

## Acknowledgments
* **Dataset:** The machine learning models in this repository were trained and evaluated using the [Insider Threat Dataset for Corporate Environments](https://www.kaggle.com/datasets/ahmeduzaki/insider-threat-dataset-for-corporate-environments) created by Ahmed Uzaki and provided via Kaggle.
> **IMPORTANT:** Any CSV dataset uploaded to the system for bulk analysis **must** strictly adhere to the structural format of this dataset.

Below is the expected field structure for data inputs:

### Identity & Background Information
| Field Name | Type | Description |
| :--- | :--- | :--- |
| `employee_department` | Categorical | The department the employee works in (e.g., IT, Engineering, Finance) |
| `employee_position` | Categorical | The employee's job title or tier |
| `employee_seniority_years` | Integer | Number of years the employee has been with the company |
| `employee_classification` | Integer | Security clearance or classification level |
| `has_criminal_record` | Boolean (0/1) | Whether the employee has a known criminal history |
| `is_contractor` | Boolean (0/1) | Flag indicating if the user is a contractor vs full-time |
| `employee_campus` | Categorical | The primary campus assigned to the employee |
| `has_medical_history` | Boolean (0/1) | Flag for medical history data (Ignored during inference) |
| `employee_origin_country` | Categorical | Employee's country of origin (Ignored during inference) |
| `has_foreign_citizenship` | Boolean (0/1) | Flag for foreign citizenship (Ignored during inference) |

### Behavioral & Access Indicators
| Field Name | Type | Description |
| :--- | :--- | :--- |
| `total_printed_pages` | Integer | Total volume of pages printed by the user |
| `num_printed_pages_off_hours` | Integer | Volume of pages printed outside standard business hours |
| `total_files_burned` | Integer | Total files copied to external media (USB/Disk) |
| `burned_from_other` | Boolean (0/1) | Files burned from a computer/campus not assigned to the user |
| `is_abroad` | Boolean (0/1) | Flag indicating if the employee is currently traveling abroad |
| `trip_day_number` | Float/Integer | The current day number of the active trip (0 if not traveling) |
| `hostility_country_level` | Integer | Risk rating of the destination country if traveling |
| `num_entries` | Integer | Number of times the user badged into the facility |
| `num_unique_campus` | Integer | Number of distinct corporate campuses visited |
| `late_exit_flag` | Boolean (0/1) | Flag indicating the user stayed unusually late |
| `entry_during_weekend` | Boolean (0/1) | Flag indicating facility access during the weekend |

### Target Variable (For Training)
| Field Name | Type | Description |
| :--- | :--- | :--- |
| `is_malicious` | Boolean (0/1) | **0** = Normal Behavior, **1** = Malicious Insider Threat |

## Technology Stack
**Backend (Machine Learning & API):**
* Python 3 & Django REST Framework (DRF)
* Scikit-Learn (Random Forest)
* Pandas & NumPy (Data preprocessing)
* Joblib (Model deserialization)

**Frontend (User Interface):**
* Vue.js 3 (Vite)
* Vuetify 3 (Material UI)
* Axios

## How to Run Locally

### 1. Backend Setup (Django)
```bash
# Navigate to the backend directory
cd backend

# Create and activate a virtual environment
python -m venv proto_env
.\proto_env\Scripts\activate

# Install requirements
pip install django djangorestframework pandas scikit-learn matplotlib joblib django-cors-headers

# Run the development server
python manage.py runserver
