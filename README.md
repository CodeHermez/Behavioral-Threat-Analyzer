# 🛡️ Aegis Threat Triage: AI-Powered Insider Threat Detection

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

### File Burning/Transfer Operations
| Field Name | Type | Description |
| :--- | :--- | :--- |
| `num_burn_requests` | Quantity | Total burn requests |
| `max_request_classification` | Categorical (1-4) | Highest classification level burned |
| `avg_request_classification` | Float (1-4) | Average classification level |
| `num_burn_requests_off_hours` | Quantity | Burn requests during unusual hours |
| `total_burn_volume_mb` | Quantity | Total data volume burned (MB) |
| `total_files_burned` | Quantity | Total number of files burned |
| `burned_from_other` | Boolean (0/1) | Burned from non-assigned campus |
| `burn_campuses` | Categorical/List | Campuses where burning occurred |

### Travel Information
| Field Name | Type | Description |
| :--- | :--- | :--- |
| `is_abroad` | Boolean (0/1) | Whether employee was abroad |
| `trip_day_number` | Sequential (1,2,3…) | Day N of the trip |
| `country_name` | Categorical | Destination country |
| `is_hostile_country_trip` | Boolean (0/1) | Trip to hostile country |
| `hostility_country_level` | Categorical/Numeric | Level of country hostility |
| `is_official_trip` | Boolean (0/1) | Official business trip |

### Access Control
| Field Name | Type | Description |
| :--- | :--- | :--- |
| `num_entries` | Quantity | Number of facility entries |
| `num_exits` | Quantity | Number of facility exits |
| `first_entry_time` | Datetime | First entry time of day |
| `last_exit_time` | Datetime | Last exit time of day |
| `total_presence_minutes` | Quantity | Total time spent in facility (minutes) |
| `entered_during_night_hours` | Boolean (0/1) | Night entry flag |
| `num_unique_campus` | Quantity | Number of different campuses visited |
| `early_entry_flag` | Boolean (0/1) | Early entry indicator (before 06:00) |
| `late_exit_flag` | Boolean (0/1) | Late exit indicator (after 22:00) |
| `entry_during_weekend` | Boolean (0/1) | Weekend entry flag |

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
