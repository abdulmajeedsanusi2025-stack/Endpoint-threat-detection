# AI-Powered Endpoint Threat Detection System (EDR)

A completely offline, local AI-powered endpoint threat detection and risk assessment system. Designed for zero cloud dependency, low resource overhead, and air-gapped security operations.

---

## 🎯 Key Capabilities

### 1. The 6 Core Real-Time Telemetry Events
The system continuously monitors and correlates the 6 critical host-level events requested:
1. **Process Name**: Executable identity, commandline execution arguments, detection of LOLBins (Living-off-the-Land Binaries), credential dumpers, cryptominers, and masquerading process names (e.g. `svch0st.exe`).
2. **CPU Usage**: Real-time processor consumption percentage per process to catch CPU-bound encryption loops and mining malware.
3. **Memory Usage**: Memory consumption (RSS in Megabytes and memory percentage).
4. **Active Network Connection**: Count of active sockets, established connections, and immediate alerts for connections on known threat/backdoor/C2 ports (e.g. `4444`, `1337`, `3333`, `8888`, etc.).
5. **File Modification in a Time Window**: Rolling 60-second sliding window tracking file creations, modifications, deletions, and renames (rapid churn detection for ransomware prevention).
6. **Process Age**: Time elapsed since process creation (in seconds), flagging infant/young processes that initiate foreign network sockets or perform abnormal I/O.

---

### 2. Multi-Class AI Risk Assessment Engine
The offline AI risk engine outputs probability distributions and composite risk scores across 4 tiers:
- **Low**: Benign baseline software and background system services ($0\% - 25\%$ Composite Risk).
- **Medium**: Anomaly behavior, compilation bursts, elevated network/memory utilization ($25\% - 50\%$ Composite Risk).
- **High**: Malicious patterns such as cryptomining, reconnaissance, and unauthorized persistence ($50\% - 75\%$ Composite Risk).
- **Critical**: Active high-severity threats such as ransomware bursts, reverse shells, and shadow copy deletions ($75\% - 100\%$ Composite Risk).

**Percentage-Based Output**:
For every process, the engine provides:
- **Calibrated Multi-Class Probabilities**:
  $$\sum [P(\text{Low}), P(\text{Medium}), P(\text{High}), P(\text{Critical})] = 100\%$$
- **Composite Risk Percentage**: Single continuous index from $0.0\%$ to $100.0\%$.
- **Explainable Behavioral Indicators**: Human-readable explanations highlighting exactly which factors elevated the risk.

---

### 3. The 7 Core SOC Dashboard Tabs
The web application is partitioned into 7 dedicated operational views:
1. **Dashboard**: Essential overview of total events, detected threats, critical alerts, endpoint status, recent activity, and threat severity charts.
2. **Endpoint Monitoring**: Prominently displays the computer's hostname (**`Champion`**), OS version, logical/physical CPU cores, RAM utilization, boot uptime, and a real-time host process inspector.
3. **Threat Detection**: Deep-dive threat view showing suspicious events, ML predictions, triggered detection rules (LOLBins, suspicious ports, miners, ransomware churn), risk scores, severity levels, and explainable reasons for detection, plus a threat simulator.
4. **Alerts & Incidents**: SOC incident response management. Track active alerts, acknowledge incidents, update investigation status (`New` $\rightarrow$ `Investigating` $\rightarrow$ `Remediated` $\rightarrow$ `Closed`), add analyst notes, and filter by severity.
5. **AI Model & Analytics**: Offline model architecture, evaluation metrics, feature importance rankings across all 13 features, risk scoring methodology, and an interactive prediction sandbox to test hypothetical process parameters.
6. **File Integrity (FIM)**: Cryptographic SHA-256 baseline monitoring of protected files, detection and flagging of unexpected modifications, tamper test probes, and a multi-folder real-time guard (Desktop, Documents, Downloads, Sandbox, Temp).
7. **Reports & History**: Search historical security events and past detections, review executive SOC summaries, and export complete audit reports in JSON or CSV format.

---

## 🏗️ Architecture

```
endpoint_threat_detection_system/
├── config.py                       # Configuration constants, thresholds, and threat signatures
├── requirements.txt                # Python dependencies (psutil, scikit-learn, flask, rich, watchdog, etc.)
├── main.py                         # Unified entry point (web, monitor, dashboard, train, simulate)
├── cli_monitor.py                  # Live rich terminal console monitor
├── backend/
│   └── app.py                      # Professional Flask REST API backend
├── web/
│   ├── index.html                  # Single-page application entry point
│   └── static/                     # Cyber SOC CSS and offline React 18 frontend
├── telemetry/
│   ├── process_collector.py        # Process name, CPU%, Mem%, Net sockets, Process Age collector
│   ├── file_monitor.py             # Multi-folder real-time monitor (5+ folders) with rolling window
│   └── telemetry_manager.py        # Unified 6-event telemetry aggregation
├── engine/
│   ├── feature_extractor.py        # Feature vector extractor from the 6 telemetry events
│   ├── dataset_generator.py        # Offline synthetic training dataset generator
│   ├── model.py                    # Calibrated Random Forest model with offline persistence
│   └── risk_engine.py              # Percentage risk calculation & explainability engine
├── simulator/
│   ├── threat_simulator.py         # Safe synthetic and sandboxed file churn threat generator
├── dashboard/
│   └── app.py                      # Interactive Streamlit Web Dashboard
├── data/
│   └── threat_model.joblib         # Persisted offline AI model weights
└── tests/
    └── test_system.py              # Unit & integration test suite (10 automated tests)
```

---

## 🚀 Quickstart & Usage

### 1. Launch the Professional Web Application (React + Flask Backend) - Default
To start the modern SOC dark-mode UI with live telemetry, multi-folder guard (5+ folders), instant alert chimes, and explainable AI:
```bash
python main.py --mode web
```
Or simply:
```bash
python main.py
```
Open `http://localhost:5000` in your browser.

### 2. Run the Live Console Monitor (Rich CLI)
To start real-time monitoring directly in your terminal:
```bash
python main.py --mode monitor
```

### 3. Launch the Interactive Streamlit Dashboard
```bash
python main.py --mode dashboard
```
Or directly: `streamlit run dashboard/app.py` at `http://localhost:8501`.

### 4. Run Automated Threat Simulation Benchmark
To test detection of Ransomware, Reverse Shells, Cryptominers, and Benign apps:
```bash
python main.py --mode simulate
```

### 5. Retrain the Offline AI Model
To retrain the calibrated model from scratch offline:
```bash
python main.py --mode train
```

### 6. Run the Test Suite
```bash
python -m unittest tests/test_system.py
```

---

## 🔒 100% Offline Assurance
- **Zero Cloud Leakage**: No external telemetry or cloud API calls are made.
- **Self-Contained Model**: All model weights, calibration matrices, and heuristics run strictly on the local machine.
- **Air-Gap Compatible**: Completely functional on isolated corporate and defense networks.
