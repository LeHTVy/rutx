
import sys
import os

def is_admin():
    """Check if the script is running with administrator privileges"""
    # Only available on Windows
    if sys.platform != 'win32':
        return False
    
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        # ctypes.windll not available
        return False
    except Exception:
        return False

def restart_as_admin():
    """Restart the current script with administrator privileges"""
    # Only works on Windows
    if sys.platform != 'win32':
        print("❌ Admin elevation is only supported on Windows")
        return False
    
    if is_admin():
        return True

    # Get the python executable and current script
    python_exe = sys.executable
    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    
    print("🚀 Attempting to elevate privileges...")
    
    try:
        import ctypes
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
    except AttributeError as e:
        print(f"❌ Failed to elevate privileges: ctypes.windll not available")
        print(f"   Platform: {sys.platform}, Python: {sys.version}")
        return False
    except Exception as e:
        print(f"❌ Failed to elevate privileges: {e}")
        return False
