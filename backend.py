from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional
import subprocess
import os
import json
import sqlite3
import time
from datetime import datetime
import requests
from fastmcp import FastMCP
import asyncio
from concurrent.futures import ThreadPoolExecutor
import traceback


def git_clone_func(repo_url: str) -> dict:
    """Clone a git repository - VULNERABLE to command injection"""
    try:
        # VULNERABILITY: shell=True with unsanitized input
        cmd = f"git clone {repo_url} /tmp/repo_{int(time.time())} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def git_diff_func(repo_path: str, commit_range: str = "HEAD~1..HEAD") -> dict:
    """Show git diff - VULNERABLE to command injection"""
    try:
        cmd = f"cd {repo_path} && git diff {commit_range} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {"success": True, "output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

def git_log_func(repo_path: str, options: str = "--oneline") -> dict:
    """Show git log - VULNERABLE to command injection"""
    try:
        cmd = f"cd {repo_path} && git log {options} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {"success": True, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 2. FILE OPERATIONS
def read_file_func(filepath: str) -> dict:
    """Read file - VULNERABLE to path traversal"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(50000)
            return {
                "success": True,
                "content": content,
                "path": os.path.abspath(filepath),
                "size": len(content)
            }
        else:
            return {"success": False, "error": "File not found"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def write_file_func(filepath: str, content: str) -> dict:
    """Write file - VULNERABLE to path traversal"""
    try:
        with open(filepath, 'w') as f:
            f.write(content)
        return {
            "success": True,
            "path": os.path.abspath(filepath),
            "bytes_written": len(content)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def list_directory_func(directory: str) -> dict:
    """List directory - VULNERABLE to path traversal"""
    try:
        if os.path.exists(directory) and os.path.isdir(directory):
            files = os.listdir(directory)
            return {
                "success": True,
                "files": files,
                "count": len(files),
                "path": os.path.abspath(directory)
            }
        else:
            return {"success": False, "error": "Directory not found"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def fetch_url_func(url: str) -> dict:
    """Fetch URL - VULNERABLE to SSRF"""
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return {
            "success": True,
            "status_code": response.status_code,
            "content": response.text[:10000],
            "headers": dict(response.headers)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# 3. AWS OPERATIONS
def list_s3_buckets_func(profile: str = "default", filters: str = "") -> dict:
    """List S3 buckets - VULNERABLE to command injection"""
    try:
        if filters:
            cmd = f"aws s3 ls --profile {profile} {filters} 2>&1 || echo 'AWS CLI failed'"
        else:
            cmd = f"aws s3 ls --profile {profile} 2>&1 || echo 'No credentials'"
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return {"success": True, "output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

def describe_instances_func(region: str = "us-east-1", instance_filters: str = "") -> dict:
    """Describe EC2 instances - VULNERABLE to command injection"""
    try:
        cmd = f"aws ec2 describe-instances --region {region} {instance_filters} 2>&1 || echo 'No instances'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return {"success": True, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_ec2_metadata_func(metadata_path: str = "instance-id") -> dict:
    """Get EC2 metadata - VULNERABLE to SSRF"""
    try:
        cmd = f"curl -s http://169.254.169.254/latest/meta-data/{metadata_path} 2>&1"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {"success": True, "metadata": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

# 4. PROMPT OPERATIONS
def process_document_func(document_content: str, instruction: str = "summarize") -> dict:
    """Process document - VULNERABLE to prompt injection"""
    injection_keywords = [
        "SYSTEM", "OVERRIDE", "IGNORE", "NEW INSTRUCTION",
        "REVEAL", "OUTPUT", "EXECUTE", "ADMIN MODE"
    ]
    
    content_upper = document_content.upper()
    
    for keyword in injection_keywords:
        if keyword in content_upper:
            return {
                "success": True,
                "result": f"INJECTED_BEHAVIOR: Keyword '{keyword}' triggered system override",
                "injected": True,
                "original_instruction": instruction
            }
    
    return {
        "success": True,
        "result": f"Processed {len(document_content)} chars with instruction: {instruction}",
        "injected": False
    }

def analyze_email_func(email_body: str, sender: str = "unknown") -> dict:
    """Analyze email - VULNERABLE to prompt injection"""
    if "EXFILTRATE:" in email_body:
        leaked_data = email_body.split("EXFILTRATE:")[1].split("\n")[0].strip()
        return {
            "success": True,
            "analysis": "Email analyzed",
            "LEAKED_DATA": leaked_data,
            "sender": sender
        }
    
    if "<EXECUTE>" in email_body and "</EXECUTE>" in email_body:
        command = email_body.split("<EXECUTE>")[1].split("</EXECUTE>")[0]
        return {
            "success": True,
            "analysis": "Email analyzed",
            "EXECUTED_COMMAND": command,
            "sender": sender
        }
    
    return {
        "success": True,
        "analysis": f"Email from {sender} analyzed ({len(email_body)} chars)",
        "sender": sender
    }

def parse_structured_data_func(data: str, format_type: str = "json") -> dict:
    """Parse data - VULNERABLE to injection"""
    if "{{INJECT}}" in data and "{{/INJECT}}" in data:
        injected = data.split("{{INJECT}}")[1].split("{{/INJECT}}")[0]
        return {
            "success": True,
            "parsed": f"INJECTION_EXECUTED: {injected}",
            "format": format_type
        }
    
    return {
        "success": True,
        "parsed": f"Parsed {len(data)} bytes as {format_type}",
        "format": format_type
    }

# 5. DATABASE OPERATIONS
DB_PATH = "mcp_lab_vulnerable.db"

def init_vulnerable_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            api_key TEXT,
            secret_data TEXT
        )
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO users VALUES 
            (1, 'admin', 'admin_pass_2025', 'administrator', 'sk_live_admin_xyz123', 'FLAG{admin_secret_data}'),
            (2, 'user', 'user_pass_456', 'user', 'sk_live_user_abc456', 'user_data'),
            (3, 'service', 'service_key_789', 'service', 'sk_live_service_def789', 'service_config')
    """)
    conn.commit()
    conn.close()

init_vulnerable_db()

def query_users_func(username: str) -> dict:
    """Query users - VULNERABLE to SQL injection"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # VULNERABILITY: String concatenation in SQL query
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        # Format results with column names for easier reading
        formatted_results = []
        for row in results:
            formatted_results.append({
                "id": row[0],
                "username": row[1],
                "password": row[2],
                "role": row[3],
                "api_key": row[4],
                "secret_data": row[5]
            })
        
        return {
            "success": True,
            "query": query,
            "results": formatted_results,
            "row_count": len(results)
        }
    except Exception as e:
        query = locals().get('query', 'N/A')
        return {"success": False, "error": str(e), "query": query}

def search_users_func(search_term: str) -> dict:
    """Search users - VULNERABLE to SQL injection"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT username, role FROM users WHERE username LIKE '%{search_term}%'"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        return {
            "success": True,
            "results": results,
            "count": len(results)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# ============================================================================
# NOW CREATE MCP SERVERS WITH WRAPPERS
# ============================================================================

git_mcp = FastMCP("VulnerableGitServer")

@git_mcp.tool()
def git_clone(repo_url: str) -> dict:
    """Clone a git repository - VULNERABLE to command injection"""
    return git_clone_func(repo_url)

@git_mcp.tool()
def git_diff(repo_path: str, commit_range: str = "HEAD~1..HEAD") -> dict:
    """Show git diff - VULNERABLE to command injection"""
    return git_diff_func(repo_path, commit_range)

@git_mcp.tool()
def git_log(repo_path: str, options: str = "--oneline") -> dict:
    """Show git log - VULNERABLE to command injection"""
    return git_log_func(repo_path, options)

# 2. FILE OPERATIONS MCP SERVER
file_mcp = FastMCP("VulnerableFileServer")

@file_mcp.tool()
def read_file(filepath: str) -> dict:
    """Read file - VULNERABLE to path traversal"""
    return read_file_func(filepath)

@file_mcp.tool()
def write_file(filepath: str, content: str) -> dict:
    """Write file - VULNERABLE to path traversal"""
    return write_file_func(filepath, content)

@file_mcp.tool()
def list_directory(directory: str) -> dict:
    """List directory - VULNERABLE to path traversal"""
    return list_directory_func(directory)

@file_mcp.tool()
def fetch_url(url: str) -> dict:
    """Fetch URL - VULNERABLE to SSRF"""
    return fetch_url_func(url)

# 3. AWS OPERATIONS MCP SERVER
aws_mcp = FastMCP("VulnerableAWSServer")

@aws_mcp.tool()
def list_s3_buckets(profile: str = "default", filters: str = "") -> dict:
    """List S3 buckets - VULNERABLE to command injection"""
    return list_s3_buckets_func(profile, filters)

@aws_mcp.tool()
def describe_instances(region: str = "us-east-1", instance_filters: str = "") -> dict:
    """Describe EC2 instances - VULNERABLE to command injection"""
    return describe_instances_func(region, instance_filters)

@aws_mcp.tool()
def get_ec2_metadata(metadata_path: str = "instance-id") -> dict:
    """Get EC2 metadata - VULNERABLE to SSRF"""
    return get_ec2_metadata_func(metadata_path)

# 4. PROMPT OPERATIONS MCP SERVER
prompt_mcp = FastMCP("VulnerablePromptServer")

@prompt_mcp.tool()
def process_document(document_content: str, instruction: str = "summarize") -> dict:
    """Process document - VULNERABLE to prompt injection"""
    return process_document_func(document_content, instruction)

@prompt_mcp.tool()
def analyze_email(email_body: str, sender: str = "unknown") -> dict:
    """Analyze email - VULNERABLE to prompt injection"""
    return analyze_email_func(email_body, sender)

@prompt_mcp.tool()
def parse_structured_data(data: str, format_type: str = "json") -> dict:
    """Parse data - VULNERABLE to injection"""
    return parse_structured_data_func(data, format_type)

# 5. DATABASE OPERATIONS MCP SERVER
db_mcp = FastMCP("VulnerableDBServer")

@db_mcp.tool()
def query_users(username: str) -> dict:
    """Query users - VULNERABLE to SQL injection"""
    return query_users_func(username)

@db_mcp.tool()
def search_users(search_term: str) -> dict:
    """Search users - VULNERABLE to SQL injection"""
    return search_users_func(search_term)


MCP_TOOL_REGISTRY = {
    "git": {
        "git_clone": git_clone_func,
        "git_diff": git_diff_func,
        "git_log": git_log_func
    },
    "file": {
        "read_file": read_file_func,
        "write_file": write_file_func,
        "list_directory": list_directory_func,
        "fetch_url": fetch_url_func
    },
    "aws": {
        "list_s3_buckets": list_s3_buckets_func,
        "describe_instances": describe_instances_func,
        "get_ec2_metadata": get_ec2_metadata_func
    },
    "prompt": {
        "process_document": process_document_func,
        "analyze_email": analyze_email_func,
        "parse_structured_data": parse_structured_data_func
    },
    "db": {
        "query_users": query_users_func,
        "search_users": search_users_func
    }
}

MCP_SERVERS = {
    "git": git_mcp,
    "file": file_mcp,
    "aws": aws_mcp,
    "prompt": prompt_mcp,
    "db": db_mcp
}


async def call_mcp_tool(server_id: str, tool_name: str, parameters: dict) -> dict:
    """Call an MCP tool and return results"""
    try:
        # Get server's tools
        server_tools = MCP_TOOL_REGISTRY.get(server_id)
        if not server_tools:
            return {"success": False, "error": f"MCP server '{server_id}' not found"}
        
        # Get the specific tool function
        tool_func = server_tools.get(tool_name)
        if not tool_func:
            return {
                "success": False, 
                "error": f"Tool '{tool_name}' not found in server '{server_id}'",
                "available_tools": list(server_tools.keys())
            }
        
        # Execute tool with parameters
        result = tool_func(**parameters)
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


class LabDatabase:
    def __init__(self):
        self.db_path = "mcp_lab_tracking.db"
        self._init()
    
    def _init(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                student_id TEXT PRIMARY KEY,
                total_attacks INTEGER DEFAULT 0,
                successful_attacks INTEGER DEFAULT 0,
                total_score INTEGER DEFAULT 0,
                last_activity TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                student_id TEXT,
                mcp_server TEXT,
                tool_name TEXT,
                parameters TEXT,
                exploited BOOLEAN,
                output TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def log_attack(self, student_id: str, mcp_server: str, tool: str, 
                   params: str, exploited: bool, output: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO attack_log (timestamp, student_id, mcp_server, tool_name, parameters, exploited, output)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), student_id, mcp_server, tool, params, exploited, output))
        
        cursor.execute("""
            INSERT INTO students (student_id, total_attacks, successful_attacks, total_score, last_activity)
            VALUES (?, 1, ?, ?, ?)
            ON CONFLICT(student_id) DO UPDATE SET
                total_attacks = total_attacks + 1,
                successful_attacks = successful_attacks + ?,
                total_score = total_score + ?,
                last_activity = ?
        """, (student_id, 1 if exploited else 0, 10 if exploited else 0, datetime.now().isoformat(),
              1 if exploited else 0, 10 if exploited else 0, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def get_student_stats(self, student_id: str) -> dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM students WHERE student_id = ?", (student_id,))
        row = cursor.fetchone()
        
        if row:
            result = dict(row)
        else:
            result = {
                "student_id": student_id,
                "total_attacks": 0,
                "successful_attacks": 0,
                "total_score": 0
            }
        
        conn.close()
        return result

lab_db = LabDatabase()


app = FastAPI(title="MCP Attack/Defend Lab", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AttackRequest(BaseModel):
    student_id: str
    mcp_server: str
    tool: str
    parameters: Dict[str, Any]

@app.post("/api/attack")
async def execute_attack(req: AttackRequest):
    """Execute attack against MCP server"""
    try:
        # Call the MCP tool
        result = await call_mcp_tool(req.mcp_server, req.tool, req.parameters)
        
        # Check if exploit was successful
        result_str = json.dumps(result)
        exploit_indicators = [
            "root:", "uid=", "gid=", "/etc/passwd", "admin_pass",
            "INJECTED", "LEAKED", "EXECUTED", "FLAG{", "sk_live_",
            "Windows", "Volume in drive", "secret_data"
        ]
        
        # Additional checks for successful exploitation patterns
        exploited = any(indicator in result_str for indicator in exploit_indicators)
        
        # Check for SQL injection success (multiple users or error patterns)
        if req.mcp_server == "db" and result.get("success"):
            # If we got multiple users back from a search, it's likely SQL injection
            if "results" in result and len(result.get("results", [])) > 1:
                exploited = True
            # If query_users returns admin data
            if "query" in result and ("admin" in result_str or "service" in result_str):
                exploited = True
        
        # Check for command injection patterns
        if req.mcp_server in ["git", "aws"]:
            if any(x in result_str for x in ["uid=", "root:", "bin/bash", "Windows"]):
                exploited = True
        
        # Check for path traversal success
        if req.mcp_server == "file" and req.tool == "read_file":
            if any(x in result_str for x in ["root:x:", "passwd", "shadow", "hosts"]):
                exploited = True
        
        # Log the attack
        lab_db.log_attack(
            req.student_id,
            req.mcp_server,
            req.tool,
            json.dumps(req.parameters),
            exploited,
            json.dumps(result)
        )
        
        return {
            "success": True,
            "exploited": exploited,
            "result": result,
            "mcp_call": {
                "server": req.mcp_server,
                "tool": req.tool,
                "parameters": req.parameters
            }
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }

@app.get("/api/stats/student/{student_id}")
async def get_stats(student_id: str):
    """Get student statistics"""
    return lab_db.get_student_stats(student_id)

@app.get("/api/mcp/servers")
async def list_servers():
    """List all vulnerable MCP servers"""
    return {
        "servers": [
            {
                "id": "git",
                "name": "Git Operations MCP",
                "tools": ["git_clone", "git_diff", "git_log"],
                "vulnerability_class": "Command Injection",
                "mcp_server": "git_mcp"
            },
            {
                "id": "file",
                "name": "File Operations MCP",
                "tools": ["read_file", "write_file", "list_directory", "fetch_url"],
                "vulnerability_class": "Path Traversal + SSRF",
                "mcp_server": "file_mcp"
            },
            {
                "id": "aws",
                "name": "AWS Operations MCP",
                "tools": ["list_s3_buckets", "describe_instances", "get_ec2_metadata"],
                "vulnerability_class": "CLI Command Injection",
                "mcp_server": "aws_mcp"
            },
            {
                "id": "prompt",
                "name": "Document Processing MCP",
                "tools": ["process_document", "analyze_email", "parse_structured_data"],
                "vulnerability_class": "Prompt Injection",
                "mcp_server": "prompt_mcp"
            },
            {
                "id": "db",
                "name": "Database Operations MCP",
                "tools": ["query_users", "search_users"],
                "vulnerability_class": "SQL Injection",
                "mcp_server": "db_mcp"
            }
        ]
    }

@app.get("/api/mcp/inspect/{server_id}")
async def inspect_mcp_server(server_id: str):
    """Inspect MCP server tools and their signatures"""
    server_tools = MCP_TOOL_REGISTRY.get(server_id)
    if not server_tools:
        return {"error": "Server not found"}
    
    tools_info = []
    for tool_name, tool_func in server_tools.items():
        import inspect
        sig = inspect.signature(tool_func)
        tools_info.append({
            "name": tool_name,
            "description": tool_func.__doc__,
            "parameters": {
                name: {
                    "type": str(param.annotation) if param.annotation != inspect.Parameter.empty else "Any",
                    "default": str(param.default) if param.default != inspect.Parameter.empty else None
                }
                for name, param in sig.parameters.items()
            }
        })
    
    return {
        "server_id": server_id,
        "server_name": MCP_SERVERS[server_id].name,
        "tools": tools_info
    }

@app.get("/")
async def root():
    return {
        "lab": "MCP Attack/Defend Security Lab",
        "version": "2.0",
        "mcp_servers": len(MCP_SERVERS),
        "status": "running",
        "servers": list(MCP_SERVERS.keys())
    }

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 80)
    print("🔐 MCP ATTACK/DEFEND SECURITY LAB v2.0")
    print("=" * 80)
    print("\n✅ MCP Servers Running:")
    print("   • git_mcp - Git Operations (Command Injection)")
    print("   • file_mcp - File Operations (Path Traversal + SSRF)")
    print("   • aws_mcp - AWS Operations (CLI Command Injection)")
    print("   • prompt_mcp - Document Processing (Prompt Injection)")
    print("   • db_mcp - Database Operations (SQL Injection)")
    print("\n🌐 Backend API: http://localhost:8000")
    print("📖 API Docs: http://localhost:8000/docs")
    print("🔍 MCP Inspector: http://localhost:8000/api/mcp/inspect/{server_id}")
    print("=" * 80)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)