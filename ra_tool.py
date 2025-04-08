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
        self._active_progress_tokens = set()

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

    def wait_for_progress_done(self, task_description: str = "analysis", timeout: float = 180.0):
        """
        Waits for rust-analyzer to finish background tasks signaled via $/progress.

        Specifically waits until all active progress tokens have received an 'end' message.
        """
        log_stderr(f"[Wait] Waiting for '{task_description}' to complete (max {timeout}s)...")
        start_time = time.monotonic()
        initial_tokens = set(self._active_progress_tokens)  # Copy tokens active *before* this wait
        log_stderr(
            f"[Wait] Initially active tokens: {initial_tokens if initial_tokens else 'None'}"
        )

        if not initial_tokens:
            log_stderr("[Wait] No tasks were active at the start of the wait.")
            # Still might need to wait for NEW tasks started by the previous action (e.g. didOpen)
            # We'll rely on the loop below to catch newly started tasks.

        processed_messages = []

        while time.monotonic() - start_time < timeout:
            if self.process.poll() is not None:
                log_stderr(
                    f"[Wait] rust-analyzer process terminated during wait (exit code: {self.process.poll()})."
                )
                return False, processed_messages  # Indicate failure

            try:
                # Poll with short timeout to remain responsive
                message = self.message_queue.get(timeout=0.2)
                processed_messages.append(message)
                message_processed = False  # Flag to check if we handled the message

                if message.get("method") == "$/progress":
                    params = message.get("params", {})
                    token = params.get("token")
                    value = params.get("value", {})
                    kind = value.get("kind")

                    if token is not None:
                        if kind == "begin":
                            self._active_progress_tokens.add(token)
                            title = value.get('title', '')
                            msg = value.get('message', '')
                            log_stderr(
                                f"[Wait Progress] BEGIN '{title}': {msg} (Token: {token}). Active: {self._active_progress_tokens}"
                            )
                            message_processed = True
                        elif kind == "report":
                            # Optionally log report messages if verbose
                            if ARGS and ARGS.verbose:
                                msg = value.get('message', '')
                                percentage = value.get('percentage', '')
                                percent_str = (
                                    f" ({percentage}%)"
                                    if isinstance(percentage, (int, float))
                                    else ""
                                )
                                log_stderr(
                                    f"[Wait Progress] REPORT (Token: {token}): {msg}{percent_str}"
                                )
                            message_processed = True  # Handled (even if just logging)
                        elif kind == "end":
                            self._active_progress_tokens.discard(
                                token
                            )  # Use discard to avoid error if not present
                            msg = value.get('message', '')
                            log_stderr(
                                f"[Wait Progress] END (Token: {token}): {msg}. Active: {self._active_progress_tokens}"
                            )
                            message_processed = True
                            # --- Check completion ---
                            # We consider the wait complete if *no* tokens are active anymore.
                            # This is simpler than tracking specific titles.
                            if not self._active_progress_tokens:
                                log_stderr(
                                    f"[Wait] All progress tasks finished after {(time.monotonic() - start_time):.2f}s."
                                )
                                return True, processed_messages  # Success!

                    else:
                        log_stderr(
                            f"[Wait Progress] Warning: Received $/progress without token: {params}"
                        )
                        message_processed = True

                # --- Handle other messages received during wait ---
                if not message_processed and "method" in message:
                    method = message['method']
                    # Log diagnostics/logs even during wait if verbose
                    if method == 'window/logMessage' and ARGS and ARGS.verbose:
                        log_stderr(f"[RA Log Wait] {message['params'].get('message', '')}")
                    elif method == 'textDocument/publishDiagnostics' and ARGS and ARGS.verbose:
                        diag_count = len(message['params'].get('diagnostics', []))
                        uri_tail = message['params'].get('uri', '').split('/')[-1]
                        log_stderr(f"[RA Diag Wait] {uri_tail}: {diag_count} diagnostics")
                    # TODO: Handle window/workDoneProgress/create if RA requires response
                    # elif method == 'window/workDoneProgress/create':
                    #    pass # Send success response back
                    elif ARGS and ARGS.verbose:
                        log_stderr(f"[RA Notify Wait] Method: {method}")

                # --- Check if initially empty set remains empty ---
                # If we started with no active tokens, and still have none after polling,
                # and some time has passed, maybe analysis was very fast or didn't trigger progress.
                # Add a small delay check to avoid exiting instantly if the first poll is empty.
                if not self._active_progress_tokens and time.monotonic() - start_time > 0.5:
                    log_stderr(
                        f"[Wait] No active progress tokens detected after {(time.monotonic() - start_time):.2f}s. Assuming complete."
                    )
                    return True, processed_messages  # Assume complete

            except queue.Empty:
                # Queue empty, check if tasks are done
                if not self._active_progress_tokens:
                    # Check again, maybe the END message was processed just before queue became empty
                    log_stderr(
                        f"[Wait] Queue empty and no active tasks remaining after {(time.monotonic() - start_time):.2f}s."
                    )
                    return True, processed_messages  # Success!
                # Otherwise, continue waiting for messages or timeout
                continue

        log_stderr(f"[Wait] Timeout ({timeout}s) reached while waiting for '{task_description}'.")
        log_stderr(f"[Wait] Still active tokens: {self._active_progress_tokens}")
        return False, processed_messages  # Indicate timeout

    def wait_for_quiescence(
        self, task_description: str = "activity", timeout: float = 60.0, idle_threshold: float = 1.5
    ):
        """Waits until no messages are received for idle_threshold seconds."""
        log_stderr(
            f"[Wait] Waiting for rust-analyzer quiescence ({task_description}, max {timeout}s, idle {idle_threshold}s)..."
        )
        start_time = time.monotonic()
        last_message_time = time.monotonic()
        processed_messages = []

        while time.monotonic() - start_time < timeout:
            if self.process.poll() is not None:
                log_stderr(
                    f"[Wait Quiesce] rust-analyzer process terminated during wait (exit code: {self.process.poll()})."
                )
                return False, processed_messages  # Indicate failure

            try:
                # Poll with short timeout
                message = self.message_queue.get(timeout=0.1)
                last_message_time = time.monotonic()  # Reset timer on message
                processed_messages.append(message)  # Store message
                message_processed = False  # Flag

                # --- Basic processing of messages received *during* wait ---
                if message.get("method") == "$/progress":
                    # Handle progress messages minimally to keep state updated
                    params = message.get("params", {})
                    token = params.get("token")
                    value = params.get("value", {})
                    kind = value.get("kind")
                    if token is not None:
                        if kind == "begin":
                            self._active_progress_tokens.add(token)
                            if ARGS and ARGS.verbose:
                                log_stderr(
                                    f"[Wait Quiesce Progress] BEGIN {token}. Active: {self._active_progress_tokens}"
                                )
                        elif kind == "end":
                            self._active_progress_tokens.discard(token)
                            if ARGS and ARGS.verbose:
                                log_stderr(
                                    f"[Wait Quiesce Progress] END {token}. Active: {self._active_progress_tokens}"
                                )
                    message_processed = True

                elif "method" in message and not message_processed:
                    method = message['method']
                    if method == 'window/logMessage' and ARGS and ARGS.verbose:
                        log_stderr(f"[RA Log Quiesce] {message['params'].get('message', '')}")
                        message_processed = True
                    elif method == 'textDocument/publishDiagnostics':
                        if ARGS and ARGS.verbose:
                            diag_count = len(message['params'].get('diagnostics', []))
                            uri_tail = message['params'].get('uri', '').split('/')[-1]
                            log_stderr(f"[RA Diag Quiesce] {uri_tail}: {diag_count} diagnostics")
                        # We see diagnostics, so reset the idle timer implicitly by falling through
                        message_processed = True  # Mark as processed
                    # Ignore window/workDoneProgress/create for now unless causing issues
                    # elif method == 'window/workDoneProgress/create':
                    #    message_processed = True # Ignore

                # --- End basic processing ---

            except queue.Empty:
                # No message received in the last 0.1s
                idle_time = time.monotonic() - last_message_time
                if idle_time > idle_threshold:
                    log_stderr(
                        f"[Wait Quiesce] Server quiescent for {idle_time:.2f}s after receiving {len(processed_messages)} messages during this wait. Proceeding."
                    )
                    return True, processed_messages  # Success
                # Else: Queue was empty, but not idle long enough yet, continue loop.
            except Exception as e:
                log_stderr(f"[Wait Quiesce] Error during quiescence wait: {e}")
                return False, processed_messages  # Indicate failure

        log_stderr(
            f"[Wait Quiesce] Timeout ({timeout}s) reached while waiting for quiescence ({task_description}) after {len(processed_messages)} messages."
        )
        return False, processed_messages  # Indicate timeout

    # --- End wait_for_quiescence ---

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
                    "window": {"workDoneProgress": True},
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
                "clientInfo": {"name": "PythonRAClientCLI", "version": "0.3"},
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
                # Use a shorter timeout here to be responsive to other messages
                message = self.message_queue.get(timeout=0.2)
                if message.get("id") == init_id:
                    init_response = message
                    break
                elif "method" in message:
                    # Handle potential early progress/log messages if needed/verbose
                    method = message['method']
                    if method == 'window/logMessage' and ARGS and ARGS.verbose:
                        log_stderr(f"[RA Log InitWait] {message['params'].get('message', '')}")
                    # Note: Technically, we might get window/workDoneProgress/create *before*
                    # the initialize response. We will ignore it for now, assuming rust-analyzer
                    # proceeds without explicit create confirmation if capability is set.
                    elif ARGS and ARGS.verbose:
                        log_stderr(f"[Main] Received other message during init wait: {method}")
                else:
                    if ARGS and ARGS.verbose:
                        log_stderr(
                            f"[Main] Received unexpected message during init wait: {message}"
                        )

            except queue.Empty:
                if self.process.poll() is not None:
                    raise RuntimeError(
                        f"RA process died during init (exit code: {self.process.poll()}). Stderr:\n{self.get_stderr_snapshot()}"
                    )
                continue  # Continue waiting if process is alive

        if init_response is None:
            raise TimeoutError(
                f"Timeout waiting for initialize response. Stderr:\n{self.get_stderr_snapshot()}"
            )
        if "error" in init_response:
            raise RuntimeError(
                f"Initialization failed: {init_response['error']}. Stderr:\n{self.get_stderr_snapshot()}"
            )

        log_stderr("[Main] Received Initialize Response.")
        self.send_notification("initialized", {})
        self._initialized.set()
        log_stderr("[Main] Sent Initialized Notification. Client is ready.")
        # No sleep needed here now, we will wait properly later
        # time.sleep(0.2)

    # Make sure notify_did_open does NOT have the hardcoded sleep anymore
    def notify_did_open(self, file_path: Path):
        if not file_path.is_file():
            log_stderr(f"[Notify] File not found for didOpen: {file_path}")
            return  # Or raise error?
        uri = file_path.as_uri()
        try:
            # Ensure file is read correctly
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    text = f.read()
            except UnicodeDecodeError:
                log_stderr(
                    f"[Notify] Warning: UTF-8 decode failed for {file_path}. Trying fallback encoding."
                )
                with open(file_path, 'r', encoding='latin-1') as f:  # Or other fallback
                    text = f.read()

            self.send_notification(
                "textDocument/didOpen",
                {"textDocument": {"uri": uri, "languageId": "rust", "version": 1, "text": text}},
            )
            log_stderr(f"[Notify] Sent didOpen for {uri}")
            # time.sleep(0.7) # <<< REMOVE or COMMENT OUT the old sleep
        except Exception as e:
            log_stderr(f"[Notify] Failed to send didOpen for {uri}: {e}")
            # Consider re-raising or handling more robustly

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

    output = {
        "status": "error",
        "message": "Command failed before execution",
        "details": None,
    }  # Default error

    client = None  # Define client initially as None

    try:
        client = RustAnalyzerLSPClient(project_root=Path.cwd())
        client.start()
        client.initialize()  # Initialize already sets _initialized event

        # --- Wait 1: Initial workspace loading/analysis (using Progress) ---
        log_stderr("[Main] Waiting for initial rust-analyzer setup (using $/progress)...")
        initial_ready, _ = client.wait_for_progress_done(
            task_description="initialization", timeout=180.0
        )
        if not initial_ready:
            # ... (handle error) ...
            print(json.dumps(output, indent=2))
            sys.exit(1)
        log_stderr("[Main] Initial setup (Progress tasks) seems complete.")

        # --- Wait 2: General Quiescence (for background indexing etc.) ---
        # Run this *always* after initial progress settles, before any command.
        log_stderr(
            "[Main] Waiting for post-initialization quiescence (e.g., background indexing)..."
        )
        # Use similar timeout/idle settings as the post-open wait, adjust as needed
        general_quiesce_ok, _ = client.wait_for_quiescence(
            task_description="post-init", timeout=120.0, idle_threshold=2.5
        )
        if not general_quiesce_ok:
            log_stderr("[Main] Warning: Server didn't fully quiet down after initial progress.")
            # Decide if this is critical enough to error out, or just warn
            # output["warning"] = "Server quiescence timeout after initialization."
        else:
            log_stderr("[Main] Post-initialization quiescence seems complete.")
        # ---

        # --- Wait 3: File-specific analysis (if applicable) ---
        if target_file:
            client.notify_did_open(target_file)

            # Wait specifically for analysis triggered by opening the file
            log_stderr(
                f"[Main] Waiting for analysis after opening {target_file.name} (using quiescence)..."
            )
            open_ready, messages_during_wait = client.wait_for_quiescence(
                task_description=f"post-open {target_file.name}", timeout=120.0, idle_threshold=2.5
            )
            if not open_ready:
                log_stderr(
                    f"[Main] Warning: rust-analyzer did not quiesce after opening file within timeout. Results might be incomplete."
                )
                # ... (optional logging/warning) ...
            else:
                log_stderr(
                    f"[Main] Analysis quiescence after opening {target_file.name} seems complete."
                )
        # --- End Wait 3 ---

        # --- Workspace Symbols Delay (Likely Redundant Now) ---
        # The General Quiescence wait should cover most indexing time.
        # We can probably remove or significantly reduce this delay. Test removing it first.
        # if args.command == "workspaceSymbols":
        #     workspace_query_delay = 0.5 # Drastically reduced or 0
        #     if workspace_query_delay > 0:
        #         log_stderr(f"[Main] Applying minimal additional delay: {workspace_query_delay}s")
        #         time.sleep(workspace_query_delay)

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
        if ARGS and ARGS.verbose and hasattr(client, 'get_stderr_snapshot'):
            output["stderr_snapshot"] = client.get_stderr_snapshot()
    except Exception as e:
        output["message"] = f"Unexpected Error: {e}"
        if ARGS and ARGS.verbose:
            import traceback

            output["traceback"] = traceback.format_exc()
            if hasattr(client, 'get_stderr_snapshot'):
                output["stderr_snapshot"] = client.get_stderr_snapshot()
    finally:
        # Ensure client reference exists before calling shutdown
        if 'client' in locals() and client:
            client.shutdown()  # shutdown now mainly logs stderr if verbose

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
