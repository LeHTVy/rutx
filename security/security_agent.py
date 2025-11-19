import json
import requests
import sys

OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_LIST_ENDPOINT = "http://localhost:11434/api/tags"
MODEL_NAME = "llama3:8b"


def get_cmdb_context(ip):
    """Mock CMDB query to retrieve asset information."""
    db = {
        "192.168.1.100": {"asset_name": "DC-01-PROD", "criticality": "High", "owner": "IT"},
        "10.0.0.5": {"asset_name": "Dev-Workstation-12", "criticality": "Low", "owner": "Ivan"}
    }
    return db.get(ip, {"asset_name": "Unknown Asset", "criticality": "Unknown"})

def get_cti_context(ip):
    """Mock CTI (Cyber Threat Intelligence) query about an IP."""
    db = {
        "1.2.3.4": {"status": "malicious", "type": "Known C2 Server", "confidence": "95%"}
    }
    return db.get(ip, {"status": "clean"})
# ----------------------------------------------------

def load_raw_log(filename):
    """Load raw log file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        return None
    except json.JSONDecodeError:
        print(f"Error: File {filename} is not valid JSON.")
        return None

def enrich_log_data(raw_log):
    """
    Combine raw log with context from CMDB and CTI.
    This is the prompt preparation step for the LLM.
    """
    enriched_data = {
        "raw_log": raw_log,
        "source_ip_context": {
            "cmdb": get_cmdb_context(raw_log["source_ip"]),
            "cti": get_cti_context(raw_log["source_ip"])
        },
        "destination_ip_context": {
            "cmdb": get_cmdb_context(raw_log["destination_ip"]),
            "cti": get_cti_context(raw_log["destination_ip"])
        }
    }
    return enriched_data

def create_system_prompt():
    """
    System Prompt - CRITICALLY IMPORTANT.
    It defines the role, task, and OUTPUT format (JSON) for the LLM.
    """
    return """
    You are an autonomous Security Analyst Agent, Tier 2 level, for a Security Operations Center (SOC).

    Your task is to analyze ENRICHED log data in real-time and make response decisions.
    You will receive a JSON object containing raw log, asset context (CMDB), and threat intelligence information (CTI).

    You MUST follow these rules:
    1.  Analyze the entire context (log, cmdb, cti) to determine severity level.
    2.  Prioritize assets with high "criticality" level.
    3.  Treat any CTI information marked as "malicious" as a serious threat.
    4.  Your output MUST BE AND ONLY BE a single valid JSON object. DO NOT add any explanation or text outside the JSON object.

    Use the following JSON format:
    {
      "threat_level": "none | low | medium | high | critical",
      "reasoning": "A brief, concise explanation for your decision.",
      "recommended_action": "Specific action to take. Examples: 'No action needed', 'Log for review', 'Create Tier 2 ticket', 'Isolate host', 'Block IP'"
    }
    """

def check_model_available():
    """Check if the model has been pulled."""
    try:
        response = requests.get(OLLAMA_LIST_ENDPOINT, timeout=5)
        response.raise_for_status()
        data = response.json()
        models = [model['name'] for model in data.get('models', [])]
        return MODEL_NAME in models, models
    except:
        return False, []

def query_ollama_agent(enriched_log_json):
    """Send enriched request to Local LLM."""

    system_prompt = create_system_prompt()
    user_data = json.dumps(enriched_log_json, indent=2)

    # Combine system prompt and user data into a single prompt
    full_prompt = f"{system_prompt}\n\nData to analyze:\n{user_data}"

    print("--- Sending enriched data to LLM ---")
    print(user_data)
    print("--------------------------------------------------")

    payload = {
        "model": MODEL_NAME,
        "prompt": full_prompt,
        "format": "json",  # Request Ollama to return JSON
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=120)
        response.raise_for_status()  # Raise error if status code is 4xx or 5xx

        # Extract JSON content from Ollama response
        response_data = response.json()
        llm_output = response_data['response']

        # Parse JSON returned by LLM
        decision = json.loads(llm_output)
        return decision

    except requests.exceptions.ConnectionError:
        print(f"Error: Cannot connect to Ollama at {OLLAMA_ENDPOINT}.")
        print(f"Make sure Ollama is running and model '{MODEL_NAME}' has been pulled.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error calling Ollama API: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Details: {e.response.text}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: LLM did not return valid JSON.")
        print(f"Raw output: {llm_output}")
        print(f"Error details: {e}")
        return None
    except KeyError as e:
        print(f"Error: Ollama response has unexpected structure.")
        print(f"Missing key: {e}")
        print(f"Received data: {response_data}")
        return None

def execute_action(decision):
    """Mock action execution (currently just 'verbal' output)."""

    print("\n--- RECEIVED DECISION FROM LLM ---")
    print(json.dumps(decision, indent=2, ensure_ascii=False))
    print("--------------------------------------------")

    # This is where real automation logic would occur
    action = decision.get("recommended_action", "No action specified").lower()

    print(f"\n✓ Recommended action: '{decision.get('recommended_action')}'")

    if "block ip" in action:
        print("→ Sending command to firewall to block IP...")
    elif "isolate host" in action:
        print("→ Sending command to EDR to isolate host...")
    elif "no action" in action:
        print("→ No action needed. Logging event.")
    else:
        print("→ Logging event for human review.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python security_agent.py <log_file.json>")
        print("Example: python security_agent.py log_normal.json")
        sys.exit(1)

    # Check if model is available
    print(f"Checking model '{MODEL_NAME}'...")
    is_available, models = check_model_available()

    if not is_available:
        print(f"\nError: Model '{MODEL_NAME}' has not been pulled.")
        if models:
            print(f"Available models: {', '.join(models)}")
            print(f"\nYou can:")
            print(f"  1. Pull the model: ollama pull {MODEL_NAME}")
            print(f"  2. Or change MODEL_NAME in the script to use one of the available models")
        else:
            print(f"No models found. Please run: ollama pull {MODEL_NAME}")
        sys.exit(1)

    print(f"✓ Model '{MODEL_NAME}' is ready\n")

    log_file = sys.argv[1]

    # 1. Load raw log
    raw_log = load_raw_log(log_file)
    if not raw_log:
        return

    # 2. Enrich context
    enriched_data = enrich_log_data(raw_log)

    # 3. Query LLM for decision
    decision = query_ollama_agent(enriched_data)

    # 4. Execute action
    if decision:
        execute_action(decision)

if __name__ == "__main__":
    main()
