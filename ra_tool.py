#!/usr/bin/env python3

import subprocess
import json
import sys
import os
import threading
import queue
import time
from pathlib import Path
import argparse
import contextlib
from typing import Optional, List, Dict, Any

# --- Configuration ---
RUST_ANALYZER_CMD = "rust-analyzer"
RESPONSE_TIMEOUT = 25

# --- Globals for Logging ---
# These will be set by argparse results
ARGS = None


# --- Logging ---
def log_stderr(*args, **kwargs):
    """Helper to print logs to stderr based on verbosity flags."""
    global ARGS
    if ARGS and ARGS.quiet:
        return
    if ARGS and ARGS.verbose:
        print("[VERBOSE]", *args, file=sys.stderr, **kwargs)
    elif not ARGS or (not ARGS.quiet and not ARGS.verbose):
        # Default: Print only if it looks like an error/warning message
        msg_str = " ".join(map(str, args)).lower()
        if "error" in msg_str or "warn" in msg_str or "fail" in msg_str:
            print(*args, file=sys.stderr, **kwargs)
        # Could add other specific essential messages here if needed


# --- LSP SymbolKind Mapping ---
# From LSP 3.17 spec
SYMBOL_KIND_MAP = {
    1: "File",
    2: "Module",
    3: "Namespace",
    4: "Package",
    5: "Class",
    6: "Method",
    7: "Property",
    8: "Field",
    9: "Constructor",
    10: "Enum",
    11: "Interface",
    12: "Function",
    13: "Variable",
    14: "Constant",
    15: "String",
    16: "Number",
    17: "Boolean",
    18: "Array",
    19: "Object",
    20: "Key",
    21: "Null",
    22: "EnumMember",
    23: "Struct",
    24: "Event",
    25: "Operator",
    26: "TypeParameter",
}

# --- LSP Communication Handling ---


class RustAnalyzerLSPClient:
    def __init__(self, project_root):
        self.project_root = Path(project_root).resolve()
        self.process = None
        self.reader_thread = None
        self.message_queue = queue.Queue()
        self.stop_reader = threading.Event()
        self.request_id_counter = 1
        self._lock = threading.Lock()
        self._initialized = threading.Event()
        self._stderr_lines = []
        self._stderr_reader_thread = None
        self._stop_stderr_reader = threading.Event()

    def _encode_message(self, message):
        json_message = json.dumps(message, separators=(",", ":"))
        json_bytes = json_message.encode("utf-8")
        header = f"Content-Length: {len(json_bytes)}\r\n\r\n".encode("utf-8")
        return header + json_bytes

    def _read_stderr(self):
        """Reads stderr lines and stores them."""
        try:
            while not self._stop_stderr_reader.is_set():
                line = self.process.stderr.readline()
                if not line:
                    break
                self._stderr_lines.append(line.decode('utf-8', errors='ignore').strip())
        except Exception as e:
            log_stderr(f"[StderrReader] Error: {e}")
        log_stderr("[StderrReader] Thread finished.")

    def _decode_message_stream(self):
        """Reads messages from stdout, decodes, and puts onto the queue."""
        buffer = b""
        content_length = None
        while not self.stop_reader.is_set():
            try:
                chunk = self.process.stdout.read(1)  # Read byte by byte
                if not chunk:
                    log_stderr("[Reader] stdout stream closed.")
                    break
                buffer += chunk

                while True:  # Process buffer until no more complete messages
                    if content_length is None:
                        if b"\r\n\r\n" in buffer:
                            header_part, rest = buffer.split(b"\r\n\r\n", 1)
                            try:
                                # Find Content-Length specifically
                                cl_header = next(
                                    h
                                    for h in header_part.split(b"\r\n")
                                    if h.lower().startswith(b"content-length:")
                                )
                                content_length = int(cl_header.split(b":")[1].strip())
                                buffer = rest
                                log_stderr(f"[Reader] Got Content-Length: {content_length}")
                            except (StopIteration, ValueError, IndexError) as e:
                                log_stderr(
                                    f"[Reader] Error parsing headers: {e}, Header part: {header_part!r}"
                                )
                                self.stop_reader.set()
                                return
                        else:
                            break
                    else:
                        if len(buffer) >= content_length:
                            json_bytes = buffer[:content_length]
                            buffer = buffer[content_length:]
                            log_stderr(
                                f"[Reader] Consumed {content_length} bytes, remaining buffer: {len(buffer)}"
                            )
                            content_length = None
                            try:
                                message = json.loads(json_bytes.decode("utf-8"))
                                log_stderr(
                                    f"[Reader] Received: {message.get('method', message.get('id', 'Unknown Message Type'))}"
                                )
                                self.message_queue.put(message)
                            except json.JSONDecodeError as e:
                                log_stderr(
                                    f"[Reader] JSON Decode Error: {e} on bytes: {json_bytes!r}"
                                )
                            except Exception as e:
                                log_stderr(f"[Reader] Error processing message: {e}")
                        else:
                            break
            except Exception as e:
                if not self.stop_reader.is_set():
                    log_stderr(f"[Reader] Error reading stdout: {e}")
                break
        log_stderr("[Reader] stdout Thread finished.")

    def start(self):
        log_stderr(f"Starting rust-analyzer for project: {self.project_root}")
        try:
            self.process = subprocess.Popen(
                [RUST_ANALYZER_CMD],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.project_root,
                bufsize=0,
            )
            log_stderr(f"rust-analyzer started (PID: {self.process.pid})")

            self.reader_thread = threading.Thread(target=self._decode_message_stream, daemon=True)
            self.reader_thread.start()
            log_stderr("[Main] stdout reader thread started.")

            self._stderr_reader_thread = threading.Thread(target=self._read_stderr, daemon=True)
            self._stderr_reader_thread.start()
            log_stderr("[Main] stderr reader thread started.")

        except FileNotFoundError:
            log_stderr(
                f"Error: '{RUST_ANALYZER_CMD}' command not found. Is rust-analyzer installed and in PATH?"
            )
            raise
        except Exception as e:
            log_stderr(f"Error starting rust-analyzer: {e}")
            raise

    def _get_next_request_id(self):
        with self._lock:
            req_id = self.request_id_counter
            self.request_id_counter += 1
            return req_id

    def send_request(self, method, params):
        if not self._initialized.is_set():
            raise RuntimeError("Client not initialized. Call initialize() first.")
        if self.process.poll() is not None:
            raise RuntimeError("rust-analyzer process has terminated.")

        request_id = self._get_next_request_id()
        request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        log_stderr(f"[Main] Sending request (ID: {request_id}): {method}")
        try:
            self.process.stdin.write(self._encode_message(request))
            self.process.stdin.flush()
        except (OSError, BrokenPipeError) as e:
            raise RuntimeError(f"Failed to send request to rust-analyzer: {e}")

        start_time = time.monotonic()
        while time.monotonic() - start_time < RESPONSE_TIMEOUT:
            try:
                message = self.message_queue.get(timeout=0.5)
                if "id" in message and message["id"] == request_id:
                    log_stderr(f"[Main] Received response for ID: {request_id}")
                    return message
                elif "method" in message:
                    if message['method'] == 'window/logMessage':
                        log_stderr(f"[RA Log] {message['params'].get('message', '')}")
                    # Ignore other notifications unless verbose
                    elif ARGS and ARGS.verbose:
                        log_stderr(
                            f"[Main] Received notification while waiting: {message['method']}"
                        )
                else:
                    log_stderr(f"[Main] Received unexpected message: {message}")

            except queue.Empty:
                if self.process.poll() is not None:
                    raise RuntimeError(
                        f"rust-analyzer process terminated unexpectedly (exit code: {self.process.poll()})."
                    )
                continue

        raise TimeoutError(f"Timeout waiting for response to request ID {request_id} ({method})")

    def send_notification(self, method, params):
        if self.process.poll() is not None:
            log_stderr(
                f"[Main] Warning: Attempting to send notification '{method}' but process terminated."
            )
            return
        notification = {"jsonrpc": "2.0", "method": method, "params": params}
        log_stderr(f"[Main] Sending notification: {method}")
        try:
            self.process.stdin.write(self._encode_message(notification))
            self.process.stdin.flush()
        except (OSError, BrokenPipeError) as e:
            log_stderr(f"[Main] Warning: Failed to send notification {method}: {e}")

    def initialize(self):
        init_id = self._get_next_request_id()
        initialize_request = {
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": {
                "processId": os.getpid(),
                "rootUri": self.project_root.as_uri(),
                "capabilities": {
                    "textDocument": {
                        "synchronization": {"dynamicRegistration": False},
                        "hover": {"contentFormat": ["markdown", "plaintext"]},
                        "definition": {},
                        "references": {},
                        "typeDefinition": {},
                        "implementation": {},
                    },
                    "workspace": {"workspaceFolders": True, "symbol": {}},
                },
                "clientInfo": {"name": "PythonRAClientCLI", "version": "0.3"},  # Ver bump
                "workspaceFolders": [
                    {"uri": self.project_root.as_uri(), "name": self.project_root.name}
                ],
            },
        }
        log_stderr(f"[Main] Sending Initialize Request (ID: {init_id})")
        self.process.stdin.write(self._encode_message(initialize_request))
        self.process.stdin.flush()

        # Wait specifically for the initialize response
        start_time = time.monotonic()
        init_response = None
        while time.monotonic() - start_time < RESPONSE_TIMEOUT:
            try:
                message = self.message_queue.get(timeout=0.5)
                if message.get("id") == init_id:
                    init_response = message
                    break
                else:
                    # Handle other messages received during init if necessary
                    log_stderr(
                        f"[Main] Received other message during init wait: {message.get('method', message.get('id'))}"
                    )
            except queue.Empty:
                if self.process.poll() is not None:
                    raise RuntimeError(
                        f"RA process died during init (exit code: {self.process.poll()})."
                    )
                continue

        if init_response is None:
            raise TimeoutError("Timeout waiting for initialize response")
        if "error" in init_response:
            raise RuntimeError(f"Initialization failed: {init_response['error']}")

        log_stderr("[Main] Received Initialize Response.")
        self.send_notification("initialized", {})
        self._initialized.set()
        log_stderr("[Main] Sent Initialized Notification. Client is ready.")
        time.sleep(0.2)

    def notify_did_open(self, file_path: Path):
        # ... (remains the same, uses log_stderr) ...
        if not file_path.is_file():
            log_stderr(f"[Notify] File not found for didOpen: {file_path}")
            return
        uri = file_path.as_uri()
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
            self.send_notification(
                "textDocument/didOpen",
                {"textDocument": {"uri": uri, "languageId": "rust", "version": 1, "text": text}},
            )
            log_stderr(f"[Notify] Sent didOpen for {uri}")
            time.sleep(0.7)
        except Exception as e:
            log_stderr(f"[Notify] Failed to send didOpen for {uri}: {e}")

    def shutdown(self):
        log_stderr("[Main] Initiating shutdown...")

        # Print captured stderr only if verbose
        if ARGS and ARGS.verbose and self._stderr_lines:
            print("\n--- Captured rust-analyzer stderr: ---", file=sys.stderr)
            for line in self._stderr_lines:
                print(line, file=sys.stderr)
            print("------------------------------------", file=sys.stderr)

    # --- LSP Command Methods (including new ones) ---

    def _get_text_document_position_params(self, file_path: Path, line: int, column: int):
        """Helper to create TextDocumentPositionParams."""
        return {
            "textDocument": {"uri": file_path.as_uri()},
            "position": {"line": line - 1, "character": column - 1},
        }

    def get_references(self, file_path: Path, line: int, column: int):
        params = self._get_text_document_position_params(file_path, line, column)
        params["context"] = {"includeDeclaration": True}
        return self.send_request("textDocument/references", params)

    def get_definition(self, file_path: Path, line: int, column: int):
        params = self._get_text_document_position_params(file_path, line, column)
        return self.send_request("textDocument/definition", params)

    def get_type_definition(self, file_path: Path, line: int, column: int):
        params = self._get_text_document_position_params(file_path, line, column)
        return self.send_request("textDocument/typeDefinition", params)

    def get_hover(self, file_path: Path, line: int, column: int):
        params = self._get_text_document_position_params(file_path, line, column)
        return self.send_request("textDocument/hover", params)

    def get_implementations(self, file_path: Path, line: int, column: int):
        """NEW: Find implementations."""
        params = self._get_text_document_position_params(file_path, line, column)
        return self.send_request("textDocument/implementation", params)

    def search_workspace_symbols(self, query: str):
        """NEW: Search workspace symbols."""
        return self.send_request("workspace/symbol", {"query": query})


# --- Result Formatting ---


def format_location(location_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Formats a single LSP Location or LocationLink target."""
    if not location_data:
        return None
    range_field = (
        location_data.get('targetRange')
        or location_data.get('range')
        or location_data.get('location', {}).get('range')
    )  # Handle WorkspaceSymbol location nesting
    if not range_field:
        return None
    uri = (
        location_data.get('targetUri')
        or location_data.get('uri')
        or location_data.get('location', {}).get('uri')
    )
    if not uri:
        return None

    return {
        "uri": uri,
        "line": range_field['start']['line'] + 1,
        "column": range_field['start']['character'] + 1,
    }


def format_location_list(lsp_response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Formats results that are a list of Locations or LocationLinks."""
    result = lsp_response.get("result")
    if result is None:
        return []
    if isinstance(result, dict):
        result = [result]
    if not isinstance(result, list):
        return []

    locations = []
    for item in result:
        formatted = format_location(item)
        if formatted:
            locations.append(formatted)
    return locations


def format_hover_result(lsp_response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Formats hover results."""
    result = lsp_response.get("result")
    if not result or not result.get("contents"):
        return None
    contents = result["contents"]
    if isinstance(contents, dict) and "kind" in contents and "value" in contents:
        return {"kind": contents["kind"], "value": contents["value"]}
    elif isinstance(contents, str):
        return {"kind": "plaintext", "value": contents}
    elif isinstance(contents, list):
        value = "\n---\n".join(
            item if isinstance(item, str) else item.get("value", "") for item in contents
        )
        return {"kind": "markdown", "value": value}
    return None


def format_symbol_list(lsp_response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """NEW: Formats workspace symbol results."""
    result = lsp_response.get("result")
    if not isinstance(result, list):
        return []

    symbols = []
    for item in result:
        kind_int = item.get("kind")
        location = format_location(item)  # Use existing formatter for location part
        if location:
            symbols.append(
                {
                    "name": item.get("name"),
                    "kind": SYMBOL_KIND_MAP.get(kind_int, f"UnknownKind({kind_int})"),
                    "location": location,
                    "containerName": item.get("containerName"),  # Optional parent symbol name
                }
            )
    return symbols


# --- Markdown Formatting ---


def format_markdown_location_list(locations: List[Dict[str, Any]]) -> str:
    """NEW: Formats a list of locations as Markdown."""
    if not locations:
        return "No locations found."
    lines = ["Found Locations:"]
    for loc in locations:
        lines.append(f"- `{loc['uri']}:{loc['line']}:{loc['column']}`")
    return "\n".join(lines)


def format_markdown_hover(hover_data: Optional[Dict[str, Any]]) -> str:
    """NEW: Formats hover data as Markdown."""
    if not hover_data:
        return "No hover information found."
    header = "### Hover Information\n\n"
    if hover_data['kind'] == 'markdown':
        return header + hover_data['value']
    else:
        # Wrap plaintext in code block
        return header + f"```\n{hover_data['value']}\n```"


def format_markdown_symbol_list(symbols: List[Dict[str, Any]]) -> str:
    """NEW: Formats workspace symbols as Markdown."""
    if not symbols:
        return "No symbols found."
    lines = ["Found Workspace Symbols:"]
    for sym in symbols:
        container = f" in `{sym['containerName']}`" if sym.get('containerName') else ""
        lines.append(f"- **{sym['name']}** (*{sym['kind']}*){container}")
        lines.append(
            f"  - Location: `{sym['location']['uri']}:{sym['location']['line']}:{sym['location']['column']}`"
        )
    return "\n".join(lines)


# --- Main Execution ---


def run_command(args):
    global ARGS
    ARGS = args  # Make args accessible to logging

    client = RustAnalyzerLSPClient(project_root=Path.cwd())
    # Default error output
    output = {"status": "error", "message": "Command failed before execution", "details": None}
    target_file = None
    if hasattr(args, 'file'):  # Check if command needs a file path
        target_file = Path(args.file).resolve()
        if not target_file.is_file():
            output["message"] = f"Input file not found: {target_file}"
            # Use print directly for final output to avoid log suppression
            print(json.dumps(output, indent=2))
            sys.exit(1)

    structured_result = None
    lsp_error = None

    try:
        client.start()
        client.initialize()
        # Only notify didOpen if we have a target file for the command
        if target_file:
            client.notify_did_open(target_file)

        if args.command == "workspaceSymbols":
            workspace_query_delay = 2.0  # Seconds - adjust if needed for larger projects
            log_stderr(
                f"[Main] Applying {workspace_query_delay}s delay for workspace symbol indexing..."
            )
            time.sleep(workspace_query_delay)

        lsp_response = None

        # --- Command Dispatch ---
        if args.command == "references":
            lsp_response = client.get_references(target_file, args.line, args.column)
            structured_result = format_location_list(lsp_response)
        elif args.command == "definition":
            lsp_response = client.get_definition(target_file, args.line, args.column)
            structured_result = format_location_list(lsp_response)
        elif args.command == "typeDefinition":
            lsp_response = client.get_type_definition(target_file, args.line, args.column)
            structured_result = format_location_list(lsp_response)
        elif args.command == "hover":
            lsp_response = client.get_hover(target_file, args.line, args.column)
            structured_result = format_hover_result(lsp_response)
        elif args.command == "implementations":  # NEW
            lsp_response = client.get_implementations(target_file, args.line, args.column)
            structured_result = format_location_list(lsp_response)
        elif args.command == "workspaceSymbols":  # NEW
            lsp_response = client.search_workspace_symbols(args.query)
            structured_result = format_symbol_list(lsp_response)
        # --- End Command Dispatch ---

        if lsp_response and "error" in lsp_response:
            lsp_error = lsp_response["error"]
            output["message"] = f"LSP error: {lsp_error.get('message', 'Unknown')}"
            output["details"] = lsp_error
        elif structured_result is not None:
            # Create success output structure (overwrites default error)
            output = {"status": "success", "result": structured_result}
        else:
            # Handle cases like valid response but null result
            output = {"status": "success", "result": None}

    except (RuntimeError, TimeoutError, FileNotFoundError) as e:
        output["message"] = f"Client Error: {e}"
        # Keep status as "error"
    except Exception as e:
        output["message"] = f"Unexpected Error: {e}"
        # Keep status as "error"
        # Consider adding traceback if verbose
        if ARGS and ARGS.verbose:
            import traceback

            output["traceback"] = traceback.format_exc()
    finally:
        client.shutdown()

    # --- Final Output ---
    # Use print directly for final output to avoid log suppression
    if args.format == "json":
        print(json.dumps(output, indent=2))
    elif args.format == "markdown":
        if output["status"] == "success":
            # Format success result as markdown
            if args.command in ["references", "definition", "typeDefinition", "implementations"]:
                print(format_markdown_location_list(output["result"]))
            elif args.command == "hover":
                print(format_markdown_hover(output["result"]))
            elif args.command == "workspaceSymbols":
                print(format_markdown_symbol_list(output["result"]))
            else:  # Fallback for potentially new commands
                print(json.dumps(output["result"], indent=2))  # Print result JSON
        else:
            # Print errors plainly in markdown mode, maybe wrap?
            print(f"**Error:** {output['message']}")
            if output.get("details"):
                print("\n**Details:**")
                print(f"```json\n{json.dumps(output['details'], indent=2)}\n```")
            if output.get("traceback"):
                print("\n**Traceback:**")
                print(f"```\n{output['traceback']}\n```")
    # Add 'text' format here if implemented later

    # Exit with non-zero status code if an error occurred
    if output["status"] == "error":
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Interact with rust-analyzer LSP for code navigation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Global Flags ---
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress all informational output (stderr)."
    )
    verbosity_group.add_argument(
        "-v", "--verbose", action="store_true", help="Enable detailed diagnostic output (stderr)."
    )

    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Output format (default: json).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="LSP command to execute")

    # --- Parser for commands requiring file/line/column ---
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("file", help="Path to the target Rust file.")
    common_parser.add_argument("line", type=int, help="Line number (1-based).")
    common_parser.add_argument("column", type=int, help="Column number (1-based).")

    # --- Subcommands using common_parser ---
    parser_refs = subparsers.add_parser(
        "references", parents=[common_parser], help="Find all references."
    )
    parser_def = subparsers.add_parser(
        "definition", parents=[common_parser], help="Go to definition."
    )
    parser_typedef = subparsers.add_parser(
        "typeDefinition", parents=[common_parser], help="Go to type definition."
    )
    parser_hover = subparsers.add_parser(
        "hover", parents=[common_parser], help="Get hover information."
    )
    parser_impl = subparsers.add_parser(
        "implementations", parents=[common_parser], help="Find implementations."
    )

    # --- Parser for workspaceSymbols ---
    parser_ws_symbols = subparsers.add_parser("workspaceSymbols", help="Search workspace symbols.")
    parser_ws_symbols.add_argument("query", help="The search string for symbols.")

    # --- Parse and Run ---
    args = parser.parse_args()
    run_command(args)
