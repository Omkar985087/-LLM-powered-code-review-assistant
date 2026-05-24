# LLM-Powered Code Review Assistant

An automated, premium first-pass code auditing application designed to identify security anti-patterns, resource leaks, syntax errors, and optimization opportunities. The system leverages a mock fine-tuned **CodeLlama-13B** classification engine layered on top of structural Python AST visitors and regex-based fallback heuristics.

---

## 🚀 Key Features

### 1. **Interactive Operational Dashboard**
- **Anti-Pattern Breakdown**: Visualization of dataset anti-patterns using a sleek Chart.js doughnut chart.
- **Repository Queue**: Dynamic selection of active repositories and pending pull requests.
- **Performance Analytics**: Visualizing epochs, validation/training loss, ROC curves, and Precision-Recall tradeoffs.

### 2. **Pull Request (PR) Auditor & Reviewer**
- **Unified Diff Viewer**: Displays clean, colored code additions and deletions with true line number tracking.
- **Inline Reviews**: CodeLlama overlays context-rich inline cards beneath vulnerable code lines, highlighting matching patterns, confidence scores, and explanations.
- **1-Click Recommended Code Repair**: Directly apply recommended secure patches (like database parameterization, with block managers, and thread locks) straight into the visual code.

### 3. **Model Playground & Sandbox**
- **Pre-Loaded Templates**: Try templates for **SQL Injection**, **Resource Leaks**, **Bare Exceptions**, **Race Conditions**, and **Insecure Deserialization**.
- **Real-Time Compilation**: Write custom Python code and run live AST review streams.
- **Interactive CLI Inference Logs**: Watch weight initializations, tokenizing streams, and logit calculations directly inside the styled CLI terminal.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.11, FastAPI, Uvicorn, AST (Abstract Syntax Trees), Pydantic
- **Frontend**: Vanilla HTML5, Premium CSS3 (Glassmorphism, custom Outfit & Fira Code typography, neon status glows), Vanilla JavaScript (ES6)
- **Visuals & Charts**: Chart.js, Lucide Icons, Prism.js (Tomorrow Night syntax highlighting)

---

## 📂 Project Structure

```bash
LLM-Powered Code Review Assistant/
│
├── app.py                  # FastAPI Application & AST Analyzer Heuristics
├── requirements.txt        # Python libraries required for the project
├── .gitignore              # Ignores local virtual environment and python cache
├── README.md               # Documentation and execution instructions
│
└── static/                 # Frontend Root Directory
    ├── index.html          # Dashboard, Sandbox, and Analytics UI structure
    ├── style.css           # Premium styling, variables, animations, and typography
    └── app.js              # State management, API handling, and interactive features
```

---

## 💻 Setup & Installation

Follow these instructions to set up and run the application locally on Windows.

### Prerequisites
Make sure you have Python 3.9+ installed on your system.

### 1. Run via Virtual Environment
The project contains a pre-configured local virtual environment (`venv`) with all required libraries. To run the FastAPI server, use the command below:

```powershell
# Open terminal inside workspace and run:
.\venv\python.exe app.py
```

*Note: Avoid running `python app.py` globally unless you have installed all requirements from `requirements.txt` on your system.*

### 2. Manual Dependency Installation (Fallback)
If you need to install the dependencies in a fresh environment, run:

```powershell
pip install -r requirements.txt
python app.py
```

---

## 🌐 Navigating the App

Once the server starts successfully, open your browser and navigate to:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

1. **Dashboard Tab**: Select a repository (e.g. `service-auth-handler`) and click on any pending PR item to audit it.
2. **PR Reviewer Tab**: Click **"Run CodeLlama Auditor"** on the selected PR, select a changed file to view the annotated inline code warnings, and click **"Apply Code Fix"**.
3. **Sandbox Tab**: Pick any sample template from the selector and click **"Analyze Code"** to see live model inference CLI logs and structural audit findings.
