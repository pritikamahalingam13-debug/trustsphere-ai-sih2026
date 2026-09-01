# TrustSphere AI – One Digital Trust & Safety Layer
## Smart India Hackathon 2026 Project

**Tagline:** "Before You Click. Before You Trust."

A unified digital safety platform that analyzes suspicious digital interactions BEFORE the user clicks a link, shares information, uploads a document, or makes a payment.

---

## 🎯 Overview

TrustSphere AI is a professional cybersecurity dashboard designed to help users identify and analyze potential threats in digital interactions. The platform provides:

- **Website Trust Analysis** - Scan URLs for suspicious patterns
- **Digital Identity Verification** - Verify consistency of person/organization details
- **Document Authenticity Checking** - Analyze uploaded documents for manipulation
- **Transaction Trust Analysis** - Verify complete payment/transaction chains
- **Real-Time Safety Assistant** - Analyze SMS, emails, and messages for threats
- **Scam Relationship Detection** - Visualize connections between suspicious entities
- **Personalized Safety Guidance** - Explanations tailored to user expertise level

---

## 🏗️ Tech Stack

### Frontend
- **React** - UI framework
- **Vite** - Build tool
- **JavaScript/JSX** - Programming language
- **CSS3** - Styling with animations
- **Responsive Design** - Mobile-friendly layout

### Backend
- **Python 3.9+** - Programming language
- **FastAPI** - Web framework
- **Pydantic** - Data validation
- **CORS** - Cross-origin support

### AI/Analysis
- **Rule-based risk scoring** - Explainable analysis engine
- **Simulated threat intelligence** - Demo data for prototype
- **Extensible architecture** - Ready for real ML/NLP integration

---

## 📁 Project Structure

```
trustsphere-ai/
├── frontend/                    # React application
│   ├── src/
│   │   ├── components/         # Reusable React components
│   │   ├── pages/              # Page components
│   │   ├── services/           # API calls
│   │   ├── data/               # Demo data
│   │   ├── styles/             # Global styles
│   │   └── App.jsx             # Main app component
│   ├── package.json
│   ├── vite.config.js
│   └── index.html
│
├── backend/                     # Python FastAPI backend
│   ├── main.py                 # FastAPI app entry point
│   ├── requirements.txt         # Python dependencies
│   ├── routes/                 # API endpoints
│   ├── services/               # Business logic
│   ├── models/                 # Data models
│   ├── data/                   # Sample data
│   └── utils/                  # Utility functions
│
└── README.md                   # This file
```

---

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ and npm
- Python 3.9+

### Installation

#### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

#### Frontend
```bash
cd frontend
npm install
npm run dev
```

Access at `http://localhost:5173`

---

## 📡 API Endpoints

- `POST /api/analyze/url` - Website trust analysis
- `POST /api/analyze/identity` - Identity verification
- `POST /api/analyze/document` - Document authenticity
- `POST /api/analyze/transaction` - Transaction analysis
- `POST /api/analyze/message` - Real-time message analysis
- `GET /api/scam-network` - Scam relationship graph
- `GET /api/dashboard` - Dashboard summary

---

## 🎯 Features

✅ Website Trust Scanner  
✅ Digital Identity Verification  
✅ Document Authenticity Checker  
✅ Transaction Trust Analyzer  
✅ Real-Time Safety Assistant  
✅ Scam Relationship Detection  
✅ Dashboard with Insights  
✅ Demo Mode with Sample Scenarios  
✅ Personalized Safety Explanations  
✅ Professional Dark Theme UI  

---

## 🔐 Trust Score Engine

**Trust Score = 100 - (Weighted Risk Factors)**

| Score | Risk Level | Status |
|-------|-----------|--------|
| 80–100 | LOW | 🟢 |
| 60–79 | MEDIUM | 🟡 |
| 40–59 | HIGH | 🟠 |
| 0–39 | CRITICAL | 🔴 |

---

## 📊 Demo Scenarios

1. **Safe Website** - amazon.in (LOW RISK)
2. **Suspicious Recruitment** - Fake job offer (HIGH RISK)
3. **Payment Scam** - UPI phishing (CRITICAL RISK)

Click "Demo Mode" to test!

---

**"Before You Click. Before You Trust."** ✅
