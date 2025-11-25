
import sys
import os

def is_admin():
    """Check if the script is running with administrator/root privileges"""
    if sys.platform == 'win32':
        # Windows: Check for Administrator
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except AttributeError:
            return False
        except Exception:
            return False
    else:
        # Linux/Unix: Check for root (UID 0)
        try:
            return os.geteuid() == 0
        except AttributeError:
            # geteuid not available (shouldn't happen on Linux)
            return False

def restart_as_admin():
    """Restart the current script with administrator/root privileges"""
    if is_admin():
        return True

    if sys.platform == 'win32':
        # Windows: Use UAC elevation
        python_exe = sys.executable
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        
        print("🚀 Attempting to elevate privileges...")
        
        try:
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                python_exe, 
                f'"{script}" {params}', 
                None, 
                1
            )
            sys.exit(0)
        except AttributeError:
            print(f"❌ Failed to elevate privileges: ctypes.windll not available")
            print(f"   Platform: {sys.platform}, Python: {sys.version}")
            return False
        except Exception as e:
            print(f"❌ Failed to elevate privileges: {e}")
            return False
    else:
        # Linux/Unix: Cannot auto-elevate, provide instructions
        print("❌ Cannot auto-elevate on Linux.")
        print("💡 Please restart with sudo:")
        print(f"   sudo {sys.executable} {' '.join(sys.argv)}")
        return False
