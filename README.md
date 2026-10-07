# AI Cloud Threat Hunter

AI Cloud Threat Hunter is a Streamlit-based security analytics dashboard for detecting anomalous cloud activity from synthetic log data. It combines a role-based login flow, simulated cloud log generation, feature preprocessing, and anomaly detection to surface suspicious events in a SOC-style interface.

## Features

- Secure login page with analyst/admin access modes
- Default seeded users:
  - Admin: `admin` / `admin123`
  - Analyst: `analyst_bob` / `user123`
- Synthetic cloud event generation for training and demo usage
- Automated preprocessing of log fields for model input
- Isolation Forest-based anomaly detection
- Real-time KPI cards and threat summaries
- Threat breakdown charts by action and country
- Filterable critical log table for investigation review

## Tech Stack

- Python 3.10+
- Streamlit
- Pandas
- Plotly
- scikit-learn
- SQLite for authentication

## Project Structure

```text
AI-Cloud-Threat-Hunter/
|-- app.py                 # Main Streamlit entry point
|-- index.html             # Static landing page
|-- login.html             # Login page template
|-- squad.html             # Additional page/template
|-- requirements.txt       # Python dependencies
|-- dataset/
|   |-- auth.db           # SQLite authentication database
|   |-- cloud_logs.csv    # Generated cloud activity dataset
|-- models/                # Saved ML artifacts
|-- pages/                 # Optional app pages
|-- utils/
|   |-- auth_db.py        # Authentication and lockout logic
|   |-- detector.py       # Threat detection logic
|   |-- explanation.py    # Explainability utilities
|   |-- generator.py      # Synthetic log generation
|   |-- login_view.py     # Login UI renderer
|   |-- preprocessing.py  # Data preparation
|   |-- rules.py          # Rule-based logic
|   |-- __init__.py
|-- assets/
|   |-- app.js
|   |-- data.js
|   |-- styles.css
|-- README.md
```

## Quick Start

1. Open a terminal in the project folder.
2. Create and activate a virtual environment:

```bash
python -m venv venv
```

On Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Launch the app:

```bash
streamlit run app.py
```

5. Open the local URL shown in the terminal, then sign in with one of the default accounts.

## First Run Behavior

On first launch, the app will automatically:

- create the `dataset/` folder if needed
- generate a synthetic `cloud_logs.csv` dataset
- initialize the SQLite auth database
- create default users if no users exist

## Default Credentials

| Role | Username | Password |
| --- | --- | --- |
| Administrator | `admin` | `admin123` |
| Security Analyst | `analyst_bob` | `user123` |

## Notes

- The dashboard uses an Isolation Forest model to flag anomalous records.
- Threats are highlighted using a SOC-style layout with summary cards and charts.
- The app uses a simulated dataset for demonstration and testing, not live production telemetry.

## License

This project is provided as a local demo application for cybersecurity analytics experimentation.
