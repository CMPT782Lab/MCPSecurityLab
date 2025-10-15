# 🔐 MCP Security Lab: Attack & Defend

A hands-on cybersecurity lab for learning to exploit and secure Model Context Protocol (MCP) servers. Students discover vulnerabilities in 5 MCP servers, craft exploits to extract sensitive data, then implement secure patches to fix the vulnerabilities.

## Vulnerability Categories

- **Git Operations** - Command Injection
- **File Operations** - Path Traversal + SSRF
- **AWS Operations** - CLI Command Injection  
- **Document Processing** - Prompt Injection
- **Database Operations** - SQL Injection

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- pip

### Install Dependencies
```bash
pip install fastapi uvicorn requests fastmcp streamlit pandas plotly
```

### Run the Lab

**Terminal 1 - Start Backend:**
```bash
python backend.py
```

**Terminal 2 - Start Frontend:**
```bash
streamlit run frontend.py
```

**Access:**
- Frontend: http://localhost:8501
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

---

## 🎯 Usage

### Attack Phase
1. Login with your student ID
2. Select an MCP server to attack
3. Choose a tool and craft malicious payloads
4. Execute attacks and capture flags/sensitive data

### Defend Phase
1. Switch to DEFEND phase
2. Select an MCP server to patch
3. Write secure FastMCP implementations
4. Submit your patched code

---

## ⚠️ Security Warning

**This lab contains intentionally vulnerable code!**
- Run only in isolated environments
- Do NOT deploy to production
- Use Docker/VM for safety

---

## 📁 Project Structure

```
mcp_security_lab/
├── backend.py        # FastAPI + MCP servers (vulnerable)
├── frontend.py       # Streamlit web interface
└── README.md         # This file
```

---

## 🔧 Troubleshooting

**Backend won't start:**
```bash
# Check port availability
lsof -i :8000
```

**Frontend can't connect:**
- Ensure backend is running on port 8000
- Check no firewall is blocking localhost

---

## 📖 Example Attack

```bash
# SQL Injection to extract admin credentials
curl -X POST http://localhost:8000/api/attack \
  -H "Content-Type: application/json" \
  -d '{
    "student_id": "student001",
    "mcp_server": "db",
    "tool": "query_users",
    "parameters": {"username": "admin'\'' OR '\''1'\''='\''1"}
  }'
```

---

**Educational Use Only** - MIT License
