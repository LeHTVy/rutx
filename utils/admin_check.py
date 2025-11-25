
import ctypes
import sys
import os
import subprocess

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def restart_as_admin():
    """Restart the current script with administrator privileges"""
    if is_admin():
        return True

    # Get the python executable and current script
    python_exe = sys.executable
    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    
    print("🚀 Attempting to elevate privileges...")
    
    try:
        # Re-run the script with ShellExecute 'runas' verb
        # This triggers the UAC prompt
        ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            python_exe, 
            f'"{script}" {params}', 
            None, 
            1
        )
        # Exit the current non-admin instance
        sys.exit(0)
    except Exception as e:
        print(f"❌ Failed to elevate privileges: {e}")
        return False
