#!/usr/bin/env python3
"""
SNODE AI - Security Node Agent Launcher
Interactive startup script with LLM configuration
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


def print_banner():
    """Print SNODE AI banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███████╗███╗   ██╗ ██████╗ ██████╗ ███████╗            ║
║   ██╔════╝████╗  ██║██╔═══██╗██╔══██╗██╔════╝            ║
║   ███████╗██╔██╗ ██║██║   ██║██║  ██║█████╗              ║
║   ╚════██║██║╚██╗██║██║   ██║██║  ██║██╔══╝              ║
║   ███████║██║ ╚████║╚██████╔╝██████╔╝███████╗            ║
║   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝            ║
║                                                           ║
║   Security Node AI - Penetration Testing Framework       ║
║   Multi-LLM Support | Shannon-Inspired Intelligence      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


def check_llm_config():
    """Check if LLM is configured, offer setup if not"""
    try:
        from llm_config import LLMConfig

        llm_config = LLMConfig()
        config = llm_config.config

        # Check if configuration exists and is valid
        if not config or "provider" not in config:
            print("\n⚠️  LLM not configured.")
            print("SNODE AI requires an LLM to operate.\n")

            choice = input("Would you like to configure an LLM now? (Y/n): ").strip().lower()
            if choice != 'n':
                config = llm_config.interactive_setup()
                return config
            else:
                print("\n❌ Cannot start without LLM configuration.")
                print("Run 'python llm_config.py' to configure later.\n")
                sys.exit(1)

        # Configuration exists - show current settings
        provider_name = LLMConfig.PROVIDERS.get(config["provider"], {}).get("name", config["provider"])
        print(f"\n✅ LLM Configured:")
        print(f"   Provider: {provider_name}")
        print(f"   Model: {config['model']}")

        # Offer to reconfigure
        print("\nOptions:")
        print("  [1] Continue with current LLM")
        print("  [2] Reconfigure LLM")
        print("  [3] Test LLM connection")
        print("  [4] Exit")

        choice = input("\nChoice (1-4) [default: 1]: ").strip()

        if choice == "2":
            config = llm_config.interactive_setup()
            return config
        elif choice == "3":
            test_llm_connection(config)
            input("\nPress Enter to continue...")
            return config
        elif choice == "4":
            print("\n👋 Goodbye!")
            sys.exit(0)
        else:
            # Continue with current config
            return config

    except Exception as e:
        print(f"\n❌ Error checking LLM configuration: {e}")
        print("Please run: python llm_config.py")
        sys.exit(1)


def test_llm_connection(config):
    """Test LLM connection"""
    print("\n🧪 Testing LLM connection...")

    try:
        from llm_client import LLMClient

        client = LLMClient(config)

        # Simple test message
        response = client.chat([
            {"role": "user", "content": "Respond with exactly: 'Connection successful'"}
        ])

        if "error" in response:
            print(f"\n❌ Connection failed: {response['error']}")
            if "hint" in response:
                print(f"   Hint: {response['hint']}")
        else:
            content = response.get("message", {}).get("content", "")
            print(f"\n✅ Connection successful!")
            print(f"   Response: {content[:100]}...")

    except Exception as e:
        print(f"\n❌ Connection test failed: {e}")


def check_requirements():
    """Check if required tools are installed"""
    print("\n🔍 Checking system requirements...")

    issues = []

    # Check Shodan API key
    from config import SHODAN_API_KEY
    if not SHODAN_API_KEY or SHODAN_API_KEY == "YOUR_API_KEY_HERE":
        issues.append("⚠️  Shodan API key not configured (OSINT features disabled)")

    # Check if data directory exists
    data_dir = Path(__file__).parent / "data"
    if not data_dir.exists():
        print(f"   Creating data directory: {data_dir}")
        data_dir.mkdir(parents=True, exist_ok=True)

    if issues:
        print("\n⚠️  Configuration warnings:")
        for issue in issues:
            print(f"   {issue}")
        print("\nYou can still use SNODE AI, but some features may be limited.")
        input("\nPress Enter to continue...")
    else:
        print("✅ All requirements met!")


def main():
    """Main entry point"""
    print_banner()

    # Check requirements
    check_requirements()

    # Check and configure LLM
    llm_config = check_llm_config()

    print("\n" + "="*60)
    print("🚀 Starting SNODE AI...")
    print("="*60)

    # Import and run the main agent
    try:
        from integrated_security_agent import main as agent_main
        agent_main()
    except KeyboardInterrupt:
        print("\n\n👋 SNODE AI terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error starting SNODE AI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
