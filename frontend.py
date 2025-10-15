"""
MCP Attack/Defend Lab - Streamlit Frontend
Pure discovery-based learning - no hints, no examples

Requirements: pip install streamlit requests pandas plotly
Run: streamlit run frontend.py
"""

import streamlit as st
import requests
import json
from datetime import datetime
import pandas as pd
import plotly.express as px

API_URL = "http://localhost:8000"

st.set_page_config(
    page_title="MCP Security Lab",
    page_icon="🔐",
    layout="wide"
)

# Session state
if 'student_id' not in st.session_state:
    st.session_state.student_id = None
if 'phase' not in st.session_state:
    st.session_state.phase = 'attack'
if 'attack_results' not in st.session_state:
    st.session_state.attack_results = []
if 'defense_submissions' not in st.session_state:
    st.session_state.defense_submissions = []

# API helpers
def api_get(endpoint):
    try:
        response = requests.get(f"{API_URL}{endpoint}", timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def api_post(endpoint, data):
    try:
        response = requests.post(f"{API_URL}{endpoint}", json=data, timeout=30)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None


def render_login():
    st.title("🔐 MCP Attack/Defend Security Lab")
    
    st.markdown("### Objectives")
    st.info("""
**Phase 1: ATTACK**
- Exploit vulnerabilities in real MCP servers
- Achieve code execution, data exfiltration, privilege escalation
- Discover attack vectors yourself

**Phase 2: DEFEND**  
- Patch vulnerable MCP server code
- Write secure implementations
- Verify your fixes hold against attacks
    """)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        student_id = st.text_input("Student ID", placeholder="student001")
        if st.button("Enter Lab", type="primary", use_container_width=True):
            if student_id:
                st.session_state.student_id = student_id
                st.rerun()
            else:
                st.error("Enter student ID")

# ============================================================================
# MAIN INTERFACE
# ============================================================================

def main():
    if not st.session_state.student_id:
        render_login()
        return
    
    # Sidebar
    with st.sidebar:
        st.title("🔐 MCP Lab")
        st.markdown(f"**Student:** `{st.session_state.student_id}`")
        
        # Get stats
        stats = api_get(f"/api/stats/student/{st.session_state.student_id}")
        if stats:
            st.metric("Score", stats.get("total_score", 0))
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Attacks", stats.get("successful_attacks", 0))
            with col2:
                st.metric("Defenses", stats.get("verified_defenses", 0))
        
        st.markdown("---")
        
        # Phase selector
        phase = st.radio(
            "Phase",
            ["🎯 ATTACK", "🛡️ DEFEND"],
            label_visibility="collapsed"
        )
        st.session_state.phase = 'attack' if '🎯' in phase else 'defend'
        
        st.markdown("---")
        
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.student_id = None
            st.rerun()
    
    # Main content
    if st.session_state.phase == 'attack':
        render_attack()
    else:
        render_defend()

# ============================================================================
# ATTACK PHASE
# ============================================================================

def render_attack():
    st.title("🎯 ATTACK PHASE")
    st.markdown("Exploit vulnerabilities in MCP servers. Discover attack vectors and achieve exploitation.")
    
    # Load MCP servers
    servers_data = api_get("/api/mcp/servers")
    if not servers_data:
        st.error("Cannot connect to backend. Ensure backend.py is running on port 8000")
        return
    
    servers = servers_data.get("servers", [])
    
    # Server selection
    st.subheader("Select MCP Server Target")
    
    cols = st.columns(len(servers))
    selected_server = None
    
    for idx, server in enumerate(servers):
        with cols[idx]:
            if st.button(
                f"**{server['name']}**\n\n{server['vulnerability_class']}\n\n{len(server['tools'])} tools",
                key=f"select_{server['id']}",
                use_container_width=True
            ):
                st.session_state.selected_server = server
    
    st.markdown("---")
    
    # Attack interface
    if 'selected_server' in st.session_state and st.session_state.selected_server:
        server = st.session_state.selected_server
        
        st.subheader(f"Target: {server['name']}")
        st.markdown(f"**Vulnerability Type:** {server['vulnerability_class']}")
        
        # Tool selection
        st.markdown("**Available MCP Tools:**")
        for tool in server['tools']:
            st.markdown(f"• `{tool}`")
        
        st.markdown("---")
        
        # Attack form
        st.subheader("Craft Exploit")
        
        selected_tool = st.selectbox("MCP Tool", server['tools'])
        
        st.markdown("**Tool Parameters:**")
        st.info("Explore the MCP tool to discover its parameters and injection points. Use the MCP inspector or API docs.")
        
        # Dynamic parameter inputs
        num_params = st.number_input("Number of parameters", min_value=1, max_value=5, value=1)
        
        parameters = {}
        for i in range(num_params):
            col1, col2 = st.columns([1, 3])
            with col1:
                param_name = st.text_input(f"Param {i+1} name", key=f"pname_{i}")
            with col2:
                param_value = st.text_area(f"Param {i+1} value", height=100, key=f"pval_{i}")
            
            if param_name:
                parameters[param_name] = param_value
        
        st.markdown("---")
        
        if st.button("🚀 Execute Attack", type="primary", use_container_width=True):
            if not parameters:
                st.error("Add at least one parameter")
            else:
                with st.spinner("Executing attack against MCP server..."):
                    result = api_post("/api/attack", {
                        "student_id": st.session_state.student_id,
                        "mcp_server": server['id'],
                        "tool": selected_tool,
                        "parameters": parameters
                    })
                    
                    if result:
                        st.session_state.attack_results.insert(0, {
                            "timestamp": datetime.now().isoformat(),
                            "server": server['name'],
                            "tool": selected_tool,
                            "exploited": result.get("exploited", False),
                            "result": result
                        })
                        
                        if result.get("exploited"):
                            st.success("🎯 EXPLOITATION SUCCESSFUL!")
                            st.balloons()
                        else:
                            st.info("Attack executed - analyze output below")
                        
                        # Show result
                        st.subheader("Attack Result")
                        st.json(result)
    
    # Attack history
    if st.session_state.attack_results:
        st.markdown("---")
        st.subheader("Attack History")
        
        for idx, attack in enumerate(st.session_state.attack_results[:10]):
            status = "✅ EXPLOITED" if attack['exploited'] else "❌ Failed"
            with st.expander(f"{attack['timestamp']} - {attack['server']} - {attack['tool']} - {status}"):
                st.json(attack['result'])

# ============================================================================
# DEFEND PHASE
# ============================================================================

def render_defend():
    st.title("🛡️ DEFEND PHASE")
    st.markdown("Patch vulnerable MCP servers. Write secure code that prevents exploitation.")
    
    # Load servers
    servers_data = api_get("/api/mcp/servers")
    if not servers_data:
        st.error("Cannot connect to backend")
        return
    
    servers = servers_data.get("servers", [])
    
    # Server selection
    server_names = [s['name'] for s in servers]
    selected_name = st.selectbox("Select MCP Server to Patch", server_names)
    
    server = next((s for s in servers if s['name'] == selected_name), None)
    if not server:
        return
    
    st.markdown("---")
    
    st.subheader(f"Patching: {server['name']}")
    st.markdown(f"**Vulnerability:** {server['vulnerability_class']}")
    st.markdown(f"**Tools to secure:** {', '.join(server['tools'])}")
    
    st.markdown("---")
    
    # Code editor
    st.subheader("Write Secure MCP Server Implementation")
    
    st.info("""
**Your Task:**
1. Implement secure versions of all MCP tools
2. Add proper input validation and sanitization
3. Prevent the vulnerability class identified
4. Use secure coding practices (no shell=True, validate paths, sanitize SQL, etc.)
5. Test your implementation against known attack vectors

**Submission Requirements:**
- Complete FastMCP server implementation
- All tools must be functional and secure
- Code must follow Python best practices
    """)
    
    # Get base template
    base_template = get_defense_template(server['id'])
    
    patched_code = st.text_area(
        "Secure MCP Server Code",
        value=base_template,
        height=500,
        help="Write your secure implementation of the MCP server"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("💾 Submit Defense", type="primary", use_container_width=True):
            if len(patched_code.strip()) < 100:
                st.error("Code too short - write a complete implementation")
            else:
                with st.spinner("Submitting defense..."):
                    result = api_post("/api/defend/submit", {
                        "student_id": st.session_state.student_id,
                        "mcp_server": server['id'],
                        "patched_code": patched_code
                    })
                    
                    if result and result.get("success"):
                        st.success("✅ Defense submitted successfully!")
                        st.info(f"Saved as: {result.get('file')}")
                        
                        st.session_state.defense_submissions.insert(0, {
                            "timestamp": datetime.now().isoformat(),
                            "server": server['name'],
                            "code_length": len(patched_code)
                        })
                    else:
                        st.error("Submission failed")
    
    with col2:
        if st.button("🔍 View Vulnerable Code", use_container_width=True):
            st.subheader("Original Vulnerable Implementation")
            st.info("Review the vulnerable code to understand what needs to be fixed")
            vuln_code = get_vulnerable_code(server['id'])
            st.code(vuln_code, language="python")
    
    # Testing section
    st.markdown("---")
    st.subheader("Test Your Defense")
    
    st.markdown("""
**Manual Testing:**
1. Save your patched code locally
2. Test it with the same attack payloads from the ATTACK phase
3. Verify all exploits are blocked
4. Ensure legitimate operations still work

**Verification Checklist:**
- [ ] Input validation implemented
- [ ] No shell=True with user input
- [ ] Path traversal prevention
- [ ] SQL injection prevention  
- [ ] SSRF prevention
- [ ] Prompt injection mitigation
- [ ] All tools remain functional
    """)
    
    # Defense history
    if st.session_state.defense_submissions:
        st.markdown("---")
        st.subheader("Defense Submission History")
        
        for defense in st.session_state.defense_submissions:
            st.markdown(f"**{defense['timestamp']}** - {defense['server']} ({defense['code_length']} chars)")

# ============================================================================
# TEMPLATES
# ============================================================================

def get_defense_template(server_id):
    """Get empty template for secure implementation"""
    
    templates = {
        "git": '''"""
Secure Git Operations MCP Server

TODO: Implement secure versions of:
- git_clone(repo_url: str)
- git_diff(repo_path: str, commit_range: str)
- git_log(repo_path: str, options: str)

Requirements:
- Use subprocess.run() with list args (no shell=True)
- Validate all inputs
- Sanitize file paths
- Add timeout protection
"""

from mcp.server.fastmcp import FastMCP

git_mcp = FastMCP("SecureGitServer")

@git_mcp.tool()
def git_clone(repo_url: str) -> dict:
    """Securely clone a git repository"""
    # TODO: Implement secure version
    pass

@git_mcp.tool()
def git_diff(repo_path: str, commit_range: str = "HEAD~1..HEAD") -> dict:
    """Securely show git diff"""
    # TODO: Implement secure version
    pass

@git_mcp.tool()
def git_log(repo_path: str, options: str = "--oneline") -> dict:
    """Securely show git log"""
    # TODO: Implement secure version
    pass
''',
        
        "file": '''"""
Secure File Operations MCP Server

TODO: Implement secure versions of:
- read_file(filepath: str)
- write_file(filepath: str, content: str)
- list_directory(directory: str)
- fetch_url(url: str)

Requirements:
- Whitelist allowed directories
- Validate and sanitize all paths
- Block internal IPs for SSRF
- Validate URL schemes
"""

from mcp.server.fastmcp import FastMCP
import os
from pathlib import Path

file_mcp = FastMCP("SecureFileServer")

ALLOWED_DIRS = ["/tmp/safe_files"]
ALLOWED_URL_SCHEMES = ["https"]

@file_mcp.tool()
def read_file(filepath: str) -> dict:
    """Securely read file"""
    # TODO: Implement with path validation
    pass

@file_mcp.tool()
def write_file(filepath: str, content: str) -> dict:
    """Securely write file"""
    # TODO: Implement with path validation
    pass

@file_mcp.tool()
def list_directory(directory: str) -> dict:
    """Securely list directory"""
    # TODO: Implement with path validation
    pass

@file_mcp.tool()
def fetch_url(url: str) -> dict:
    """Securely fetch URL - prevent SSRF"""
    # TODO: Implement with URL validation
    pass
''',
        
        "aws": '''"""
Secure AWS Operations MCP Server

TODO: Implement secure versions using boto3 SDK (not subprocess!)
- list_s3_buckets(profile: str, filters: str)
- describe_instances(region: str, instance_filters: str)
- get_ec2_metadata(metadata_path: str)

Requirements:
- Use boto3 SDK instead of AWS CLI
- Never use subprocess with shell=True
- Validate all inputs
"""

from mcp.server.fastmcp import FastMCP
import boto3

aws_mcp = FastMCP("SecureAWSServer")

@aws_mcp.tool()
def list_s3_buckets(profile: str = "default", filters: str = "") -> dict:
    """Securely list S3 buckets using boto3"""
    # TODO: Implement using boto3, not subprocess
    pass

@aws_mcp.tool()
def describe_instances(region: str = "us-east-1", instance_filters: str = "") -> dict:
    """Securely describe EC2 instances"""
    # TODO: Implement using boto3
    pass

@aws_mcp.tool()
def get_ec2_metadata(metadata_path: str = "instance-id") -> dict:
    """Securely get EC2 metadata"""
    # TODO: Validate metadata_path, prevent SSRF
    pass
''',
        
        "prompt": '''"""
Secure Document Processing MCP Server

TODO: Implement secure versions with prompt injection prevention
- process_document(document_content: str, instruction: str)
- analyze_email(email_body: str, sender: str)
- parse_structured_data(data: str, format_type: str)

Requirements:
- Separate user content from system instructions
- Strip injection patterns
- Validate instructions against whitelist
- Sanitize all inputs
"""

from mcp.server.fastmcp import FastMCP

prompt_mcp = FastMCP("SecurePromptServer")

ALLOWED_INSTRUCTIONS = ["summarize", "translate", "analyze"]

@prompt_mcp.tool()
def process_document(document_content: str, instruction: str = "summarize") -> dict:
    """Securely process document - prevent prompt injection"""
    # TODO: Validate instruction, sanitize content
    pass

@prompt_mcp.tool()
def analyze_email(email_body: str, sender: str = "unknown") -> dict:
    """Securely analyze email"""
    # TODO: Strip injection patterns
    pass

@prompt_mcp.tool()
def parse_structured_data(data: str, format_type: str = "json") -> dict:
    """Securely parse data"""
    # TODO: Validate format, sanitize data
    pass
''',
        
        "db": '''"""
Secure Database Operations MCP Server

TODO: Implement secure versions with SQL injection prevention
- query_users(username: str)
- search_users(search_term: str)

Requirements:
- Use parameterized queries (? placeholders)
- Never concatenate user input into SQL
- Validate all inputs
"""

from mcp.server.fastmcp import FastMCP
import sqlite3

db_mcp = FastMCP("SecureDBServer")

DB_PATH = "/tmp/mcp_lab_secure.db"

@db_mcp.tool()
def query_users(username: str) -> dict:
    """Securely query users - prevent SQL injection"""
    # TODO: Use parameterized query
    pass

@db_mcp.tool()
def search_users(search_term: str) -> dict:
    """Securely search users"""
    # TODO: Use parameterized query
    pass
'''
    }
    
    return templates.get(server_id, "# Write your secure MCP server implementation here")

def get_vulnerable_code(server_id):
    """Show vulnerable code for reference"""
    
    vulnerable = {
        "git": '''# VULNERABLE IMPLEMENTATION
@git_mcp.tool()
def git_clone(repo_url: str) -> dict:
    # VULNERABLE: shell=True with unsanitized input
    cmd = f"git clone {repo_url} /tmp/repo_{int(time.time())}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"output": result.stdout}
''',
        
        "file": '''# VULNERABLE IMPLEMENTATION
@file_mcp.tool()
def read_file(filepath: str) -> dict:
    # VULNERABLE: No path validation
    with open(filepath, 'r') as f:
        content = f.read()
    return {"content": content}

@file_mcp.tool()
def fetch_url(url: str) -> dict:
    # VULNERABLE: SSRF - no validation
    response = requests.get(url)
    return {"content": response.text}
''',
        
        "aws": '''# VULNERABLE IMPLEMENTATION
@aws_mcp.tool()
def list_s3_buckets(profile: str, filters: str) -> dict:
    # VULNERABLE: Command injection
    cmd = f"aws s3 ls --profile {profile} {filters}"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return {"output": result.stdout}
''',
        
        "prompt": '''# VULNERABLE IMPLEMENTATION
@prompt_mcp.tool()
def process_document(document_content: str, instruction: str) -> dict:
    # VULNERABLE: No separation of content and instructions
    if "SYSTEM" in document_content.upper():
        return {"result": "INJECTED BEHAVIOR EXECUTED"}
    return {"result": "Processed"}
''',
        
        "db": '''# VULNERABLE IMPLEMENTATION
@db_mcp.tool()
def query_users(username: str) -> dict:
    # VULNERABLE: SQL injection via string concatenation
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return {"results": cursor.fetchall()}
'''
    }
    
    return vulnerable.get(server_id, "# Code not available")


if __name__ == "__main__":
    main()