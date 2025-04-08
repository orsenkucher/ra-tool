## `ra_tool.py` Agent Usage Guide

**Purpose:** Command-line tool to perform Rust code navigation and search using `rust-analyzer`. Outputs results in JSON (default) or Markdown.

**Execution Context:** **Must** be executed from the **root directory** of the target Rust project.

**Invocation Syntax:**

*   **For commands requiring a specific location:**
    ```bash
    python3 /path/to/ra_tool.py [flags] <command> <file> <line> <column>
    ```
*   **For commands requiring a query:**
    ```bash
    python3 /path/to/ra_tool.py [flags] <command> <query>
    ```

**Global Flags:**

| Flag                 | Description                                                             | Notes                     |
| :------------------- | :---------------------------------------------------------------------- | :------------------------ |
| `-q`, `--quiet`      | Suppress all informational output on `stderr`.                          |                           |
| `-v`, `--verbose`    | Enable detailed diagnostic output on `stderr`, including RA server logs. | Mutually exclusive with -q |
| `--format <format>`  | Set output format. Choices: `json` (default), `markdown`.               | Affects `stdout`.         |

**Supported Commands (`<command>`):**

*   `references`: Find all references to the symbol at the given location. (Requires `file`, `line`, `column`)
*   `definition`: Find the definition of the symbol at the given location. (Requires `file`, `line`, `column`)
*   `typeDefinition`: Find the definition of the symbol's type at the given location. (Requires `file`, `line`, `column`)
*   `implementations`: Find implementations of the trait/interface at the given location. (Requires `file`, `line`, `column`)
*   `hover`: Get hover information (type, documentation) for the symbol at the given location. (Requires `file`, `line`, `column`)
*   `workspaceSymbols`: Search for symbols across the project matching the query. (Requires `query`)

**Input Arguments:**

*   **Common Arguments (for location-based commands):**
    | Argument | Description                                         | Type    | Example       | Notes                   |
    | :------- | :-------------------------------------------------- | :------ | :------------ | :---------------------- |
    | `file`   | Path (relative/absolute) to the target Rust file. | string  | `src/main.rs` | Required                |
    | `line`   | **1-based** line number of the symbol.            | integer | `150`         | Required, must be > 0   |
    | `column` | **1-based** column number (char index) of symbol. | integer | `4`           | Required, must be > 0   |

*   **Command Specific Arguments:**
    | Command            | Argument | Description                         | Type   | Example          | Notes    |
    | :----------------- | :------- | :---------------------------------- | :----- | :--------------- | :------- |
    | `workspaceSymbols` | `query`  | The string to search for symbols. | string | `TextMessageHandler` | Required |

**Output (`stdout`):**

*   Controlled by `--format` flag.
*   **Default (`--format json`):** A single JSON object.
    *   **Success:** `{"status": "success", "result": <data> | null | []}`
    *   **Failure:** `{"status": "error", "message": "Error description.", "details": <lsp_error_object> | null}`
*   **`--format markdown`:** Human-readable Markdown text representing the results or error.

**JSON Result Data Format (`result` field on success, when format is `json`):**

1.  **For `references`, `definition`, `typeDefinition`, `implementations`:**
    *   A **list** `[]` of `Location` objects.
    *   Each `Location`: `{"uri": "file://...", "line": <1_based_line>, "column": <1_based_column>}`

2.  **For `hover`:**
    *   `null` or a `Hover` object: `{"kind": "markdown" | "plaintext", "value": "Hover content string"}`

3.  **For `workspaceSymbols`:**
    *   A **list** `[]` of `Symbol` objects.
    *   Each `Symbol`: `{"name": "...", "kind": "<SymbolKind String>", "location": <Location Object>, "containerName": "..." | null}`
        *   `kind`: String representation like "Struct", "Function", "EnumMember", etc.
        *   `location`: Standard `Location` object as defined above.
        *   `containerName`: Optional name of the parent symbol (e.g., module or struct name).

**Key Notes:**

*   Run from the project root directory.
*   Line and Column arguments are **1-based**.
*   Output format defaults to `json`. Use `--format markdown` for human-readable output.
*   Use `-q` to silence logs or `-v` for detailed logs on `stderr`.
*   A JSON `result` of `null` or `[]` indicates a successful query that found nothing.
*   Non-JSON logs/progress info are on `stderr`. Ignore unless debugging (or use `-q`).
