"""
HexStrike Tools Module
Comprehensive security tools wrapped for SNODE LangChain agent
"""

import os
import json
import shutil
from datetime import datetime
from pathlib import Path
from utils.command_runner import CommandRunner


# ============================================================================
# TOOL EXECUTABLE DISCOVERY
# ============================================================================

def _find_tool_executable(tool_name: str, venv_name: str = None) -> str:
    """Find tool executable, checking venvs and common paths"""
    
    # Known Go security tools - check Go paths FIRST (before system PATH)
    # This is important because some tools like httpx have Python packages with same name
    go_tools = ["httpx", "nuclei", "subfinder", "katana", "dalfox", "gau", "naabu"]
    
    # Get project root for venv path
    project_root = Path(__file__).parent.parent.parent  # advanced_tools.py -> tools -> snode_langchain -> rutx
    
    # Check venv locations - both current user and hellrazor (for sudo)
    home = os.path.expanduser("~")
    homes_to_check = [home]
    if home != "/home/hellrazor":
        homes_to_check.append("/home/hellrazor")
    
    venv_paths = []
    
    # For Go tools, check Go paths FIRST
    if tool_name in go_tools:
        for h in homes_to_check:
            venv_paths.append(f"{h}/go/bin/{tool_name}")
        venv_paths.append(f"/usr/local/go/bin/{tool_name}")
    
    # Check project venv first (for pip-installed tools like arjun, bbot)
    venv_paths.append(str(project_root / "venv" / "bin" / tool_name))
    venv_paths.append("/home/hellrazor/rutx/venv/bin/" + tool_name)
    
    # Then check user venvs and local paths
    for h in homes_to_check:
        venv_paths.extend([
            f"{h}/tool-venvs/{venv_name or tool_name}-venv/bin/{tool_name}",
            f"{h}/.local/bin/{tool_name}",
        ])
    
    # Check system-wide locations
    venv_paths.extend([
        f"/opt/{tool_name}/bin/{tool_name}",
        f"/snap/bin/{tool_name}",
    ])
    
    # Check venv paths first
    for path in venv_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    # Finally check system PATH
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path
    
    return tool_name  # Fallback


# ============================================================================
# NUCLEI - Vulnerability Scanner
# ============================================================================

def nuclei_scan(target: str, severity: str = "critical,high", tags: str = None, 
                templates: str = None, timeout: int = 600) -> dict:
    """
    Run Nuclei vulnerability scanner on target.
    
    Args:
        target: URL or host to scan
        severity: Severity filter (critical,high,medium,low,info)
        tags: Template tags to use (e.g., "cve,rce,sqli")
        templates: Specific template path
        timeout: Timeout in seconds
    """
    try:
        nuclei_bin = _find_tool_executable("nuclei")
        
        cmd = [nuclei_bin, "-u", target, "-severity", severity, "-json", "-silent"]
        
        if tags:
            cmd.extend(["-tags", tags])
        if templates:
            cmd.extend(["-t", templates])
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        if not exec_result.success:
            return {"success": False, "error": exec_result.error, "target": target}
        
        # Parse JSON output
        vulnerabilities = []
        for line in exec_result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    vuln = json.loads(line)
                    vulnerabilities.append({
                        "template": vuln.get("template-id", "unknown"),
                        "name": vuln.get("info", {}).get("name", "Unknown"),
                        "severity": vuln.get("info", {}).get("severity", "unknown"),
                        "matched": vuln.get("matched-at", ""),
                        "type": vuln.get("type", "")
                    })
                except json.JSONDecodeError:
                    continue
        
        return {
            "success": True,
            "tool": "nuclei",
            "target": target,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities[:50],
            "severity_filter": severity,
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"Nuclei scan: {len(vulnerabilities)} vulnerabilities found",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": target}


# ============================================================================
# HTTPX - HTTP Probe
# ============================================================================

def httpx_probe(targets: str, tech_detect: bool = True, status_code: bool = True,
                timeout: int = 300) -> dict:
    """
    Probe HTTP services using httpx.
    
    Args:
        targets: URL, domain, or file path with targets
        tech_detect: Enable technology detection
        status_code: Show status codes
        timeout: Timeout in seconds
    """
    try:
        httpx_bin = _find_tool_executable("httpx")
        
        cmd = [httpx_bin, "-u", targets, "-json", "-silent"]
        
        if tech_detect:
            cmd.append("-tech-detect")
        if status_code:
            cmd.append("-status-code")
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        if not exec_result.success:
            return {"success": False, "error": exec_result.error, "target": targets}
        
        # Parse JSON output
        results = []
        for line in exec_result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    result = json.loads(line)
                    results.append({
                        "url": result.get("url", ""),
                        "status_code": result.get("status_code", 0),
                        "title": result.get("title", ""),
                        "technologies": result.get("tech", []),
                        "content_length": result.get("content_length", 0)
                    })
                except json.JSONDecodeError:
                    continue
        
        return {
            "success": True,
            "tool": "httpx",
            "target": targets,
            "hosts_found": len(results),
            "results": results[:100],
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"httpx probe: {len(results)} live hosts",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": targets}


# ============================================================================
# FFUF - Web Fuzzer
# ============================================================================

def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              extensions: str = None, threads: int = 40, timeout: int = 600) -> dict:
    """
    Fuzz web paths using ffuf.
    
    Args:
        url: Target URL with FUZZ keyword (e.g., http://target.com/FUZZ)
        wordlist: Path to wordlist
        extensions: File extensions to add (e.g., "php,html,js")
        threads: Number of threads
        timeout: Timeout in seconds
    """
    try:
        ffuf_bin = _find_tool_executable("ffuf")
        
        # Ensure FUZZ keyword in URL
        if "FUZZ" not in url:
            url = url.rstrip('/') + "/FUZZ"
        
        cmd = [ffuf_bin, "-u", url, "-w", wordlist, "-t", str(threads), "-o", "/tmp/ffuf_out.json", "-of", "json", "-s"]
        
        if extensions:
            cmd.extend(["-e", extensions])
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        # Parse JSON output
        results = []
        try:
            with open("/tmp/ffuf_out.json", 'r') as f:
                data = json.load(f)
                for result in data.get("results", []):
                    results.append({
                        "url": result.get("url", ""),
                        "status": result.get("status", 0),
                        "length": result.get("length", 0),
                        "words": result.get("words", 0)
                    })
        except:
            pass
        
        return {
            "success": True,
            "tool": "ffuf",
            "target": url,
            "paths_found": len(results),
            "results": results[:100],
            "wordlist": wordlist,
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"ffuf: {len(results)} paths discovered",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "ffuf not found. Install: go install github.com/ffuf/ffuf/v2@latest"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": url}


# ============================================================================
# GOBUSTER - Directory Bruteforce
# ============================================================================

def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                 extensions: str = None, threads: int = 10, timeout: int = 600) -> dict:
    """
    Directory bruteforce using gobuster.
    
    Args:
        url: Target URL
        wordlist: Path to wordlist
        extensions: File extensions (e.g., "php,html,txt")
        threads: Number of threads
        timeout: Timeout in seconds
    """
    try:
        gobuster_bin = _find_tool_executable("gobuster")
        
        cmd = [gobuster_bin, "dir", "-u", url, "-w", wordlist, "-t", str(threads), "-q"]
        
        if extensions:
            cmd.extend(["-x", extensions])
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        if not exec_result.success:
            return {"success": False, "error": exec_result.error, "target": url}
        
        # Parse output
        results = []
        for line in exec_result.stdout.strip().split('\n'):
            if line.strip() and '(Status:' in line:
                results.append(line.strip())
        
        return {
            "success": True,
            "tool": "gobuster",
            "target": url,
            "paths_found": len(results),
            "results": results[:100],
            "wordlist": wordlist,
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"gobuster: {len(results)} paths discovered",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "gobuster not found. Install: go install github.com/OJ/gobuster/v3@latest"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": url}


# ============================================================================
# SQLMAP - SQL Injection Scanner
# ============================================================================

def sqlmap_scan(url: str, forms: bool = True, batch: bool = True, 
                level: int = 1, risk: int = 1, timeout: int = 600) -> dict:
    """
    SQL injection testing using sqlmap.
    
    Args:
        url: Target URL with parameter (e.g., http://target.com/page?id=1)
        forms: Test forms automatically
        batch: Run in batch mode (no user interaction)
        level: Test level (1-5)
        risk: Risk level (1-3)
        timeout: Timeout in seconds
    """
    try:
        sqlmap_bin = _find_tool_executable("sqlmap", "sqlmap")
        
        cmd = [sqlmap_bin, "-u", url, "--level", str(level), "--risk", str(risk)]
        
        if forms:
            cmd.append("--forms")
        if batch:
            cmd.append("--batch")
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        # Parse output for findings
        output = exec_result.stdout
        injectable = "is vulnerable" in output.lower() or "injectable" in output.lower()
        
        return {
            "success": True,
            "tool": "sqlmap",
            "target": url,
            "injectable": injectable,
            "output": output[-3000:] if len(output) > 3000 else output,
            "level": level,
            "risk": risk,
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"sqlmap: {'VULNERABLE' if injectable else 'No injection found'}",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "sqlmap not found. Install in venv: ~/tool-venvs/sqlmap-venv/bin/pip install sqlmap"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": url}


# ============================================================================
# NIKTO - Web Server Scanner
# ============================================================================

def nikto_scan(url: str, timeout: int = 600) -> dict:
    """
    Web server vulnerability scan using nikto.
    
    Args:
        url: Target URL or host
        timeout: Timeout in seconds
    """
    try:
        nikto_bin = _find_tool_executable("nikto")
        
        cmd = [nikto_bin, "-h", url, "-Format", "json", "-o", "/tmp/nikto_out.json"]
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        # Parse JSON output
        vulnerabilities = []
        try:
            with open("/tmp/nikto_out.json", 'r') as f:
                data = json.load(f)
                for vuln in data.get("vulnerabilities", []):
                    vulnerabilities.append({
                        "id": vuln.get("id", ""),
                        "msg": vuln.get("msg", ""),
                        "method": vuln.get("method", ""),
                        "url": vuln.get("url", "")
                    })
        except:
            # Parse text output as fallback
            for line in exec_result.stdout.split('\n'):
                if '+ ' in line:
                    vulnerabilities.append({"msg": line.strip()})
        
        return {
            "success": True,
            "tool": "nikto",
            "target": url,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities[:50],
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"nikto: {len(vulnerabilities)} findings",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "nikto not found. Install: apt install nikto"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": url}


# ============================================================================
# RUSTSCAN - Fast Port Scanner
# ============================================================================

def rustscan_fast(target: str, ports: str = None, ulimit: int = 5000, 
                  timeout: int = 300) -> dict:
    """
    Ultra-fast port scanning using rustscan.
    
    Args:
        target: IP address or hostname
        ports: Port range (e.g., "1-65535") or None for all
        ulimit: File descriptor limit
        timeout: Timeout in seconds
    """
    try:
        rustscan_bin = _find_tool_executable("rustscan")
        
        cmd = [rustscan_bin, "-a", target, "--ulimit", str(ulimit), "-g"]
        
        if ports:
            cmd.extend(["-p", ports])
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        if not exec_result.success:
            return {"success": False, "error": exec_result.error, "target": target}
        
        # Parse output for open ports
        open_ports = []
        for line in exec_result.stdout.split('\n'):
            # rustscan outputs ports in format: "Open 192.168.1.1:22"
            if 'Open' in line or ':' in line:
                try:
                    port = int(line.split(':')[-1].strip())
                    open_ports.append(port)
                except:
                    continue
        
        return {
            "success": True,
            "tool": "rustscan",
            "target": target,
            "open_ports": sorted(set(open_ports)),
            "open_ports_count": len(set(open_ports)),
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"rustscan: {len(set(open_ports))} open ports",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "rustscan not found. Install: cargo install rustscan"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": target}


# ============================================================================
# DALFOX - XSS Scanner
# ============================================================================

def dalfox_xss(url: str, param: str = None, timeout: int = 300) -> dict:
    """
    XSS vulnerability scanning using dalfox.
    
    Args:
        url: Target URL with parameters
        param: Specific parameter to test
        timeout: Timeout in seconds
    """
    try:
        dalfox_bin = _find_tool_executable("dalfox")
        
        cmd = [dalfox_bin, "url", url, "--silence", "-o", "/tmp/dalfox_out.json", "--format", "json"]
        
        if param:
            cmd.extend(["-p", param])
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        # Parse JSON output
        vulnerabilities = []
        try:
            with open("/tmp/dalfox_out.json", 'r') as f:
                for line in f:
                    if line.strip():
                        vuln = json.loads(line)
                        vulnerabilities.append(vuln)
        except:
            pass
        
        return {
            "success": True,
            "tool": "dalfox",
            "target": url,
            "xss_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities[:20],
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"dalfox: {len(vulnerabilities)} XSS vulnerabilities found",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "dalfox not found. Install: go install github.com/hahwul/dalfox/v2@latest"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": url}


# ============================================================================
# ARJUN - Parameter Discovery
# ============================================================================

def arjun_params(url: str, method: str = "GET", timeout: int = 300) -> dict:
    """
    Hidden parameter discovery using arjun.
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST)
        timeout: Timeout in seconds
    """
    try:
        arjun_bin = _find_tool_executable("arjun", "arjun")
        
        cmd = [arjun_bin, "-u", url, "-m", method, "-oJ", "/tmp/arjun_out.json"]
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        # Parse JSON output
        params = []
        try:
            with open("/tmp/arjun_out.json", 'r') as f:
                data = json.load(f)
                for url_key, param_list in data.items():
                    params.extend(param_list)
        except:
            pass
        
        return {
            "success": True,
            "tool": "arjun",
            "target": url,
            "parameters_found": len(params),
            "parameters": params[:50],
            "method": method,
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"arjun: {len(params)} hidden parameters discovered",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "arjun not found. Install in venv: ~/tool-venvs/arjun-venv/bin/pip install arjun"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": url}


# ============================================================================
# GAU - GetAllUrls
# ============================================================================

def gau_urls(domain: str, timeout: int = 300) -> dict:
    """
    Fetch known URLs from various sources using gau.
    
    Args:
        domain: Target domain
        timeout: Timeout in seconds
    """
    try:
        gau_bin = _find_tool_executable("gau")
        
        cmd = [gau_bin, domain]
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        if not exec_result.success:
            return {"success": False, "error": exec_result.error, "target": domain}
        
        # Parse URLs
        urls = [u.strip() for u in exec_result.stdout.split('\n') if u.strip()]
        
        return {
            "success": True,
            "tool": "gau",
            "target": domain,
            "urls_found": len(urls),
            "urls": urls[:200],
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"gau: {len(urls)} URLs discovered",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "gau not found. Install: go install github.com/lc/gau/v2/cmd/gau@latest"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": domain}


# ============================================================================
# WAYBACKURLS - Wayback Machine URLs
# ============================================================================

def waybackurls(domain: str, timeout: int = 300) -> dict:
    """
    Fetch URLs from Wayback Machine.
    
    Args:
        domain: Target domain
        timeout: Timeout in seconds
    """
    try:
        wayback_bin = _find_tool_executable("waybackurls")
        
        # waybackurls reads from stdin
        cmd = ["echo", domain, "|", wayback_bin]
        
        print(f"  Running: echo {domain} | waybackurls")
        
        import subprocess
        result = subprocess.run(
            f"echo {domain} | {wayback_bin}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        urls = [u.strip() for u in result.stdout.split('\n') if u.strip()]
        
        return {
            "success": True,
            "tool": "waybackurls",
            "target": domain,
            "urls_found": len(urls),
            "urls": urls[:200],
            "summary": f"waybackurls: {len(urls)} archived URLs found",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "waybackurls not found. Install: go install github.com/tomnomnom/waybackurls@latest"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": domain}


# ============================================================================
# KATANA - Web Crawler
# ============================================================================

def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True, 
                 timeout: int = 300) -> dict:
    """
    Web crawling using katana.
    
    Args:
        url: Target URL
        depth: Crawl depth
        js_crawl: Enable JavaScript crawling
        timeout: Timeout in seconds
    """
    try:
        katana_bin = _find_tool_executable("katana")
        
        cmd = [katana_bin, "-u", url, "-d", str(depth), "-silent", "-jc" if js_crawl else ""]
        cmd = [c for c in cmd if c]  # Remove empty strings
        
        print(f"  Running: {' '.join(cmd)}")
        
        exec_result = CommandRunner.run(cmd, timeout=timeout)
        
        if not exec_result.success:
            return {"success": False, "error": exec_result.error, "target": url}
        
        urls = [u.strip() for u in exec_result.stdout.split('\n') if u.strip()]
        
        return {
            "success": True,
            "tool": "katana",
            "target": url,
            "urls_found": len(urls),
            "urls": urls[:200],
            "depth": depth,
            "js_crawl": js_crawl,
            "elapsed_seconds": round(exec_result.elapsed_time, 2),
            "command": ' '.join(cmd),
            "summary": f"katana: {len(urls)} URLs crawled",
            "timestamp": datetime.now().isoformat()
        }
        
    except FileNotFoundError:
        return {"success": False, "error": "katana not found. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"}
    except Exception as ex:
        return {"success": False, "error": str(ex), "target": url}


# ============================================================================
# TOOL DEFINITIONS FOR LANGCHAIN
# ============================================================================

ADVANCED_TOOLS = [
    {
        "name": "nuclei_scan",
        "description": "Vulnerability scanning using nuclei with templates. Detects CVEs, misconfigurations, and security issues. Use for: vulnerability scan, CVE detection, security audit.",
        "func": nuclei_scan,
        "args": ["target", "severity", "tags"]
    },
    {
        "name": "httpx_probe",
        "description": "HTTP probe to check live hosts and detect technologies. Use for: check if hosts are alive, technology detection, HTTP fingerprinting.",
        "func": httpx_probe,
        "args": ["targets", "tech_detect", "status_code"]
    },
    {
        "name": "ffuf_fuzz",
        "description": "Web fuzzing using ffuf for directory/file discovery. Use for: directory brute force, file discovery, fuzzing web paths.",
        "func": ffuf_fuzz,
        "args": ["url", "wordlist", "extensions"]
    },
    {
        "name": "gobuster_dir",
        "description": "Directory brute forcing using gobuster. Use for: find hidden directories, enumerate web paths.",
        "func": gobuster_dir,
        "args": ["url", "wordlist", "extensions"]
    },
    {
        "name": "sqlmap_scan",
        "description": "SQL injection testing using sqlmap. Use for: SQLi detection, database exploitation, injection testing.",
        "func": sqlmap_scan,
        "args": ["url", "forms", "batch", "level", "risk"]
    },
    {
        "name": "nikto_scan",
        "description": "Web server vulnerability scanning using nikto. Use for: web server audit, vulnerability detection, misconfigurations.",
        "func": nikto_scan,
        "args": ["url"]
    },
    {
        "name": "rustscan_fast",
        "description": "Ultra-fast port scanning using rustscan. Use for: quick port scan, fast reconnaissance, port discovery.",
        "func": rustscan_fast,
        "args": ["target", "ports", "ulimit"]
    },
    {
        "name": "dalfox_xss",
        "description": "XSS vulnerability scanning using dalfox. Use for: XSS detection, cross-site scripting testing.",
        "func": dalfox_xss,
        "args": ["url", "param"]
    },
    {
        "name": "arjun_params",
        "description": "Hidden parameter discovery using arjun. Use for: find hidden parameters, API parameter enumeration.",
        "func": arjun_params,
        "args": ["url", "method"]
    },
    {
        "name": "gau_urls",
        "description": "Fetch known URLs from AlienVault, Wayback, Common Crawl. Use for: passive URL collection, historical URLs.",
        "func": gau_urls,
        "args": ["domain"]
    },
    {
        "name": "waybackurls",
        "description": "Fetch archived URLs from Wayback Machine. Use for: historical URLs, find old endpoints.",
        "func": waybackurls,
        "args": ["domain"]
    },
    {
        "name": "katana_crawl",
        "description": "Web crawling with JavaScript rendering. Use for: deep web crawling, endpoint discovery, JavaScript analysis.",
        "func": katana_crawl,
        "args": ["url", "depth", "js_crawl"]
    }
]


def get_advanced_tool_functions():
    """Return tool functions for LangChain integration"""
    return {tool["name"]: tool["func"] for tool in ADVANCED_TOOLS}


def get_advanced_tool_descriptions():
    """Return tool descriptions for agent prompt"""
    descriptions = []
    for tool in ADVANCED_TOOLS:
        descriptions.append(f"- {tool['name']}: {tool['description']}")
    return "\n".join(descriptions)
