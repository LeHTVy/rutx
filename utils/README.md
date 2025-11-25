# SNODE AI Utilities

Interactive input handling with command history and keyboard navigation support.

## Features

### InteractiveInput
- **Arrow Key Navigation**: Use ↑/↓ to navigate command history
- **Cursor Movement**: Use ←/→ to move cursor (when readline available)
- **Tab Completion**: Auto-complete support (when readline available)
- **Cross-Platform**: Works on Linux, macOS, and Windows

### HistoryManager
- **Persistent History**: Commands saved to `~/.snode_history`
- **Duplicate Prevention**: Avoids consecutive duplicate commands
- **Size Limit**: Configurable max history (default: 1000 commands)
- **Thread-Safe**: Safe for concurrent access

## Usage

### Basic Usage

```python
from utils import create_input_handler

# Create input handler with history
input_handler = create_input_handler(
    prompt="SNODE> ",
    history_file=".snode_history"
)

# Get user input with history support
while True:
    user_input = input_handler.input()
    if user_input == "quit":
        break
    # Process input...
```

### Advanced Usage

```python
from utils import InteractiveInput, HistoryManager

# Create custom history manager
history = HistoryManager(
    history_file=".my_history",
    max_history=500
)

# Create input handler
input_handler = InteractiveInput(
    prompt="$ ",
    history_manager=history
)

# Get input
command = input_handler.input()

# Access history
all_history = input_handler.get_history()
print(f"History: {len(all_history)} commands")

# Clear history
input_handler.clear_history()
```

## Keyboard Shortcuts

### Unix/Linux/macOS (with readline)
- **↑** - Previous command in history
- **↓** - Next command in history
- **←** - Move cursor left
- **→** - Move cursor right
- **Ctrl+A** - Move to beginning of line
- **Ctrl+E** - Move to end of line
- **Ctrl+K** - Delete from cursor to end
- **Ctrl+U** - Delete entire line
- **Ctrl+C** - Interrupt (KeyboardInterrupt)
- **Ctrl+D** - EOF (exit on empty line)
- **Tab** - Auto-complete

### Windows (with msvcrt)
- **↑** - Previous command in history
- **↓** - Next command in history
- **←** - Move cursor left
- **→** - Move cursor right
- **Backspace** - Delete previous character
- **Ctrl+C** - Interrupt (KeyboardInterrupt)
- **Ctrl+D** - EOF

## History File Format

The history is stored in pickle format at `~/.snode_history` by default. The file contains:
- List of command strings
- Limited to max_history size
- Automatically trimmed on save

## Platform Support

| Platform | Readline | Arrow Keys | Tab Complete | Cursor Edit |
|----------|----------|------------|--------------|-------------|
| Linux    | ✅       | ✅         | ✅           | ✅          |
| macOS    | ✅       | ✅         | ✅           | ✅          |
| Windows  | ⚠️       | ✅         | ❌           | ⚠️          |

- ✅ Full support
- ⚠️ Partial support (basic features only)
- ❌ Not supported

## Examples

### Example 1: Simple CLI

```python
from utils import create_input_handler

input_handler = create_input_handler(prompt="> ")

while True:
    cmd = input_handler.input()
    if cmd == "quit":
        break
    print(f"You entered: {cmd}")
```

### Example 2: View History

```python
input_handler = create_input_handler()

# Show last 10 commands
history = input_handler.get_history()
for i, cmd in enumerate(history[-10:], 1):
    print(f"{i}. {cmd}")
```

### Example 3: Custom History Location

```python
from pathlib import Path

# Store history in project directory
project_dir = Path(__file__).parent
history_file = project_dir / ".project_history"

input_handler = create_input_handler(
    prompt="PROJECT> ",
    history_file=str(history_file)
)
```

## Error Handling

The module handles errors gracefully:

```python
try:
    user_input = input_handler.input()
except KeyboardInterrupt:
    print("\nInterrupted by user")
except EOFError:
    print("\nEOF received")
```

## Thread Safety

The `HistoryManager` is designed to be thread-safe for file operations. However, for concurrent usage in multi-threaded applications, consider using locks around `add()` operations.

## Customization

### Custom Prompt

```python
# Dynamic prompt
def get_prompt():
    import datetime
    return f"[{datetime.datetime.now():%H:%M:%S}] > "

while True:
    cmd = input_handler.input(prompt=get_prompt())
```

### Filter Commands

```python
# Don't save certain commands to history
cmd = input_handler.input()
if cmd not in ["clear", "help", "history"]:
    input_handler.history_manager.add(cmd)
```
