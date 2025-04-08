# Guide for Claude Code: Using ra_tool.py with Rust Codebases

## Overview

`ra_tool.py` is a powerful command-line tool that helps Claude Code analyze Rust codebases semantically using rust-analyzer. It enables intelligent code navigation that goes beyond simple text search.

## Setup Requirements

- Must be run from the **root directory** of the Rust project
- Python 3 must be installed
- rust-analyzer must be available in the environment

## Key Commands and Workflows

### Finding References

To find all references to a function/variable/type:

1. First locate the definition line using ripgrep:
   ```bash
   rg -n "^fn function_name" src/path/to/file.rs
   ```

2. Then use ra_tool to find all references:
   ```bash
   python3 ra_tool.py references src/path/to/file.rs <line> <column>
   ```

### Finding Implementations

To find implementations of a trait:

```bash
python3 ra_tool.py implementations src/path/to/file.rs <line> <column>
```

### Finding Definitions

To jump to the definition of a symbol:

```bash
python3 ra_tool.py definition src/path/to/file.rs <line> <column>
```

### Getting Hover Information

To get type information and documentation:

```bash
python3 ra_tool.py hover src/path/to/file.rs <line> <column>
```

### Searching for Symbols

To find a symbol across the entire workspace:

```bash
python3 ra_tool.py workspaceSymbols <symbol_name>
```

## Output Formats

- Use `--format markdown` for human-readable output
- Default JSON output is ideal for programmatic parsing

## Workflow Tips

1. Use ripgrep (rg) to quickly find code locations
2. Use ra_tool.py for semantic analysis of those locations
3. Combine with BatchTool for parallel operations
4. Use `-q` for quiet mode or `-v` for verbose debugging

## Example Workflow

```
# First find where a function is defined
rg -n "^fn process_message" src/

# Then find all references to that function
python3 ra_tool.py --format markdown references src/main.rs 150 4

# Find implementations of a trait
python3 ra_tool.py --format markdown implementations src/main.rs 42 15

# Search for a specific type across workspace
python3 ra_tool.py --format markdown workspaceSymbols TextMessageHandler
```

Remember that line and column numbers are 1-based in ra_tool.py.