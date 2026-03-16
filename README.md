<h1 align="center">🛡️ CrashWise</h1>

<p align="center">
  <strong>Autonomous AI-Powered Fuzzing & Crash Triage Platform</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License: Apache 2.0"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"/></a>
  <img src="https://img.shields.io/badge/temporal-✓-purple" alt="Temporal">
  <img src="https://img.shields.io/badge/streamlit-✓-red" alt="Streamlit">
  <img src="https://img.shields.io/badge/docker-✓-blue" alt="Docker">
  <a href="https://github.com/YahyaToubali/Crashwise/stargazers"><img src="https://img.shields.io/github/stars/YahyaToubali/Crashwise?style=social" alt="GitHub Stars"></a>
</p>

<p align="center">
  <sub>
    <a href="#-features"><b>Features</b></a>
    • <a href="#-screenshots"><b>Screenshots</b></a>
    • <a href="#-installation"><b>Installation</b></a>
    • <a href="#-quick-start"><b>Quick Start</b></a>
    • <a href="#-architecture"><b>Architecture</b></a>
    • <a href="#-environment-variables"><b>Configuration</b></a>
    • <a href="#-contributing"><b>Contributing</b></a>
  </sub>
</p>

---

## 🎯 What is CrashWise?

**CrashWise** is an autonomous security testing platform that combines continuous fuzzing with intelligent crash analysis:

- **🤖 AI-Powered Triage**: LLM-based vulnerability assessment, exploitability scoring, and automatic GitHub issue creation
- **🎯 Self-Healing Coverage**: Detects coverage stalls and intelligently responds with seed mutations, harness variants, and parameter adjustments
- **📊 Web Dashboard**: Real-time campaign monitoring, crash visualization, and coverage tracking
- **🔔 Smart Notifications**: Slack/Discord alerts for high-severity crashes
- **📤 SARIF Export**: Generate SARIF reports for CI/CD integration

> **Zero-effort fuzzing**: Upload a binary → CrashWise analyzes it, generates a harness, creates seeds, fuzzes it, triages crashes, and reports bugs.

---

## ✨ Features

### AI Auto-Mode
- Binary analysis (language detection, entry points, symbols)
- Automatic fuzz harness generation (C, C++, Python, Go)
- LLM-generated seed corpus
- AFL dictionary creation

### Continuous Fuzzing
- AFL++ integration with crash monitoring
- Coverage progress tracking with stall detection
- Automatic crash collection and deduplication

### Intelligent Triage
- ASan/UBSan/GDB crash parsing
- LLM-powered vulnerability classification
- Exploitability scoring (1-10)
- ChromaDB semantic deduplication

### Self-Healing Coverage
- Automatic stall detection
- Supervisor decides: mutate seeds, change params, new harness, add dictionary
- Continuous optimization loop

### Web Dashboard
- Real-time campaign list with status
- Crash cards with severity badges
- Coverage line charts
- SARIF export buttons
- Campaign launch forms

### Integrations
- GitHub issue creation (auto-report high-severity bugs)
- Slack/Discord notifications
- SARIF export for security scanners

---

## 📸 Screenshots

### Dashboard Home
> *Dashboard showing campaign list, quick stats, and recent activity*

The main dashboard shows all fuzzing campaigns with real-time status, crash counts, and coverage progress.

### Campaigns Page
> *Campaign list with filtering, export options, and coverage charts*

Filter by status (running/completed/failed), view coverage history, and export campaign data.

### Crashes Page
> *Crash triage results with severity badges, exploitability scores, and PoC downloads*

Detailed crash cards showing vulnerability class, exploitability score, triage JSON, and PoC download links.

### Start New Campaign
> *Form for launching new fuzz campaigns with auto-mode toggle*

Configure target binary, duration, seed corpus, and enable AI auto-mode for zero-effort fuzzing.

---

## 📦 Installation

### Prerequisites
- Docker & Docker Compose
- 8GB RAM minimum (16GB recommended)
- Linux or macOS

### Quick Install

```bash
# Clone the repository
git clone https://github.com/YahyaToubali/Crashwise.git
cd Crashwise

# Copy environment template
cp volumes/env/.env.template volumes/env/.env

# Edit .env and add your API keys
# Required: OPENCODE_API_KEY (get from opencode.ai/auth)
# Optional: GITHUB_TOKEN, SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL

# Start services
docker compose up -d

# Check status
docker compose ps
```

### Services
| Service | Port | Description |
|---------|------|-------------|
| Dashboard | 8501 | Streamlit web UI |
| Temporal UI | 8080 | Workflow visualization |
| MinIO Console | 9001 | Object storage browser |
| LLM Proxy | 10999 | LiteLLM proxy UI |

---

## 🚀 Quick Start

### Option 1: Dashboard (Recommended)

1. Open http://localhost:8501
2. Go to **Start New** page
3. Enter target binary path (or upload)
4. Toggle **Auto Mode** ✓
5. Click **Launch Campaign**
6. Watch crashes appear in real-time

### Option 2: CLI

```bash
# Install CLI
pip install crashwise-cli

# Start autonomous fuzz campaign
cw auto /path/to/binary --duration 2h --model opencode/minimax-m2.5

# Check status
cw fuzz status <campaign-id> --live

# List all campaigns
cw fuzz list
```

### Example: Fuzz a Binary

```bash
# Start campaign with CLI
cw fuzz start ./target_binary \
  --seeds ./corpus \
  --duration 4h \
  --max-crashes 100 \
  --triage \
  --minimize

# Monitor progress
cw fuzz status <id> --live

# View crash results
cw fuzz crashes <id>
```

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CrashWise Platform                        │
├─────────────────────────────────────────────────────────────────┤
│  Web Dashboard (Streamlit)    │    CLI (Typer)                  │
├─────────────────────────────────────────────────────────────────┤
│                      Temporal Workflow Engine                    │
├──────────────┬──────────────┬──────────────┬──────────────────┤
│   Crash       │  Continuous  │    Auto      │   Crash Triage   │
│   Triage      │   Fuzz       │   Fuzz       │   Supervisor     │
│   Pipeline    │  Campaign    │  Campaign    │   (LangGraph)    │
├──────────────┴──────────────┴──────────────┴──────────────────┤
│                     Workers (Docker Containers)                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Crash Triage │  │    AFL++    │  │   LLM Proxy │            │
│  │   Worker     │  │   Fuzzer    │  │  (LiteLLM)  │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│  MinIO (Storage)  │  Temporal Server  │  ChromaDB (Vectors)   │
└─────────────────────────────────────────────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system design.

---

## ⚙️ Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCODE_API_KEY` | ✓ | - | OpenCode Go API key for LLM triage |
| `GITHUB_TOKEN` | ○ | - | GitHub token for issue creation |
| `GITHUB_REPO` | ○ | - | Target repo for issues (owner/repo) |
| `SLACK_WEBHOOK_URL` | ○ | - | Slack webhook for notifications |
| `DISCORD_WEBHOOK_URL` | ○ | - | Discord webhook for notifications |
| `LITELLM_BASE_URL` | | `http://llm-proxy:4000/v1` | LLM proxy endpoint |
| `TEMPORAL_ADDRESS` | | `temporal:7233` | Temporal server address |
| `MINIO_ENDPOINT` | | `http://minio:9000` | MinIO storage endpoint |

---

## 📁 Project Structure

```
CrashWise/
├── backend/           # FastAPI backend + Temporal workflows
│   ├── src/          # API endpoints
│   └── toolbox/      # Workflow definitions & activities
├── frontend/
│   └── dashboard/    # Streamlit web UI
├── workers/
│   └── crash-triage/ # Crash analysis worker
├── cli/              # Typer CLI
├── sdk/              # Python SDK
└── volumes/          # Docker volumes (env, data)
```

---

## 🧪 Testing

```bash
# Run all tests
make test

# Run specific workflow tests
pytest backend/tests/workflows/test_auto_fuzz_campaign.py

# Run with coverage
pytest --cov=backend --cov=cli
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [Temporal](https://temporal.io/) - Workflow orchestration
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) - Fuzzing framework
- [LangGraph](https://github.com/langchain-ai/langgraph) - Agent orchestration
- [Streamlit](https://streamlit.io/) - Dashboard framework
- [ChromaDB](https://www.trychroma.com/) - Vector database

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/YahyaToubali">Yahya Toubali</a>
</p>