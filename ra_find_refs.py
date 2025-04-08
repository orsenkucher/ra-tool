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

# --- Configuration ---
# Adjust if your rust-analyzer is not in PATH
RUST_ANALYZER_CMD = "rust-analyzer"
# Timeout for waiting for responses in seconds
RESPONSE_TIMEOUT = 10

# --- LSP Communication Handling ---


def encode_message(message):
    """Encodes a Python dictionary into a JSON-RPC message string."""
    json_message = json.dumps(message, separators=(",", ":"))
    json_bytes = json_message.encode("utf-8")
    header = f"Content-Length: {len(json_bytes)}\r\n\r\n".encode("utf-8")
    return header + json_bytes


def decode_message_stream(readable_stream, message_queue, stop_event):
    """
    Reads messages from the readable_stream, decodes them,
    and puts them onto the message_queue.
    Runs in a separate thread.
    """
    buffer = b""
    content_length = None
    while not stop_event.is_set():
        try:
            # Read small chunks to avoid blocking forever if no data
            chunk = readable_stream.read(1)
            if not chunk:
                # Stream closed
                print("[Reader] Stream closed.", file=sys.stderr)
                break
            buffer += chunk

            # Process buffer content
            while True:
                if content_length is None:
                    # Try to find Content-Length header
                    if b"\r\n\r\n" in buffer:
                        header_part, rest = buffer.split(b"\r\n\r\n", 1)
                        headers = header_part.split(b"\r\n")
                        for header in headers:
                            if header.lower().startswith(b"content-length:"):
                                try:
                                    content_length = int(header.split(b":")[1].strip())
                                    buffer = rest  # Keep only the part after headers
                                    # print(f"[Reader] Found Content-Length: {content_length}", file=sys.stderr)
                                    break
                                except (ValueError, IndexError):
                                    print(
                                        f"[Reader] Error parsing Content-Length header: {header}",
                                        file=sys.stderr,
                                    )
                                    # Potentially corrupted stream, decide how to handle
                                    stop_event.set()  # Stop processing
                                    return
                        if content_length is None:
                            # Found \r\n\r\n but no valid Content-Length
                            print(f"[Reader] Invalid headers: {header_part}", file=sys.stderr)
                            stop_event.set()
                            return
                    else:
                        # Need more data for headers
                        break
                else:
                    # We have content_length, check if buffer has enough data
                    if len(buffer) >= content_length:
                        json_bytes = buffer[:content_length]
                        buffer = buffer[content_length:]  # Keep the remainder
                        content_length = None  # Reset for next message
                        try:
                            message = json.loads(json_bytes.decode("utf-8"))
                            # print(f"[Reader] Received Message: {message}", file=sys.stderr)
                            message_queue.put(message)
                        except json.JSONDecodeError as e:
                            print(f"[Reader] JSON Decode Error: {e}", file=sys.stderr)
                            print(f"[Reader] Invalid JSON bytes: {json_bytes!r}", file=sys.stderr)
                        except Exception as e:
                            print(f"[Reader] Error processing message: {e}", file=sys.stderr)
                    else:
                        # Need more data for message body
                        break
        except Exception as e:
            # Catch errors during read, e.g., if process terminates unexpectedly
            if not stop_event.is_set():  # Avoid error message during clean shutdown
                print(f"[Reader] Error reading from stream: {e}", file=sys.stderr)
            break
    print("[Reader] Thread finished.", file=sys.stderr)


# --- Main Script Logic ---


def main(file_path, line, column):
    # Validate inputs
    target_file = Path(file_path).resolve()  # Get absolute path
    if not target_file.is_file():
        print(f"Error: File not found: {target_file}", file=sys.stderr)
        sys.exit(1)
    if line <= 0 or column <= 0:
        print("Error: Line and column must be positive integers.", file=sys.stderr)
        sys.exit(1)

    # Convert path to file URI
    root_uri = Path.cwd().resolve().as_uri()
    target_uri = target_file.as_uri()

    # LSP uses 0-based indexing
    lsp_line = line - 1
    lsp_character = column - 1

    print(f"Starting rust-analyzer for project at: {Path.cwd()}", file=sys.stderr)
    print(f"Finding references for: {target_uri} at line {line}, col {column}", file=sys.stderr)

    message_queue = queue.Queue()
    stop_reader = threading.Event()
    process = None
    reader_thread = None
    request_id_counter = 1

    try:
        # Start rust-analyzer process
        process = subprocess.Popen(
            [RUST_ANALYZER_CMD],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,  # Capture stderr too
            bufsize=0,  # Try unbuffered IO
        )
        print(f"rust-analyzer process started (PID: {process.pid})", file=sys.stderr)

        # Start the reader thread
        reader_thread = threading.Thread(
            target=decode_message_stream,
            args=(process.stdout, message_queue, stop_reader),
            daemon=True,  # Allow script to exit even if reader hangs (shouldn't happen with stop_event)
        )
        reader_thread.start()
        print("[Main] Reader thread started.", file=sys.stderr)

        # 1. Send Initialize Request
        init_id = request_id_counter
        request_id_counter += 1
        initialize_request = {
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": {
                "processId": os.getpid(),
                "rootUri": root_uri,
                "capabilities": {
                    "textDocument": {
                        "synchronization": {"dynamicRegistration": False},
                        "completion": {"completionItem": {"snippetSupport": True}},
                        "hover": {"contentFormat": ["markdown", "plaintext"]},
                        "references": {},  # Indicate we support references
                    },
                    "workspace": {"workspaceFolders": True, "didChangeConfiguration": {}},
                },
                "clientInfo": {"name": "PythonRAClient", "version": "0.1"},
                "workspaceFolders": [{"uri": root_uri, "name": Path.cwd().name}],
            },
        }
        print(f"[Main] Sending Initialize Request (ID: {init_id})", file=sys.stderr)
        process.stdin.write(encode_message(initialize_request))
        process.stdin.flush()

        # 2. Wait for Initialize Response
        print(f"[Main] Waiting for Initialize Response (ID: {init_id})...", file=sys.stderr)
        try:
            init_response = message_queue.get(timeout=RESPONSE_TIMEOUT)
            if init_response.get("id") != init_id:
                raise TimeoutError(f"Received unexpected message ID: {init_response.get('id')}")
            if "error" in init_response:
                print(f"Error during initialization: {init_response['error']}", file=sys.stderr)
                return  # Exit here or handle more gracefully
            print("[Main] Received Initialize Response.", file=sys.stderr)
            # You could inspect init_response['result']['capabilities'] here
        except queue.Empty:
            print(
                f"Error: Timeout waiting for initialize response after {RESPONSE_TIMEOUT}s",
                file=sys.stderr,
            )
            # Check stderr from rust-analyzer
            stderr_output = process.stderr.read()
            if stderr_output:
                print("--- rust-analyzer stderr ---", file=sys.stderr)
                print(stderr_output.decode('utf-8', errors='ignore'), file=sys.stderr)
                print("----------------------------", file=sys.stderr)
            raise TimeoutError("Initialization failed")

        # 3. Send Initialized Notification
        initialized_notification = {"jsonrpc": "2.0", "method": "initialized", "params": {}}
        print("[Main] Sending Initialized Notification", file=sys.stderr)
        process.stdin.write(encode_message(initialized_notification))
        process.stdin.flush()
        time.sleep(0.1)  # Give server a moment to process

        # Optional: Send textDocument/didOpen if needed (sometimes helps RA build state)
        try:
            with open(target_file, 'r', encoding='utf-8') as f:
                file_content = f.read()
            did_open_notification = {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": target_uri,
                        "languageId": "rust",
                        "version": 1,
                        "text": file_content,
                    }
                },
            }
            print(f"[Main] Sending textDocument/didOpen for {target_uri}", file=sys.stderr)
            process.stdin.write(encode_message(did_open_notification))
            process.stdin.flush()
            time.sleep(0.5)  # Give server time to analyze
        except Exception as e:
            print(
                f"[Main] Warning: Could not read or send didOpen for {target_uri}: {e}",
                file=sys.stderr,
            )

        # 4. Send textDocument/references Request
        ref_id = request_id_counter
        request_id_counter += 1
        references_request = {
            "jsonrpc": "2.0",
            "id": ref_id,
            "method": "textDocument/references",
            "params": {
                "textDocument": {"uri": target_uri},
                "position": {"line": lsp_line, "character": lsp_character},
                "context": {"includeDeclaration": True},
            },
        }
        print(f"[Main] Sending References Request (ID: {ref_id})", file=sys.stderr)
        process.stdin.write(encode_message(references_request))
        process.stdin.flush()

        # 5. Wait for References Response
        print(f"[Main] Waiting for References Response (ID: {ref_id})...", file=sys.stderr)
        try:
            # Consume potential progress messages first
            while True:
                response = message_queue.get(timeout=RESPONSE_TIMEOUT)
                if response.get("id") == ref_id:
                    ref_response = response
                    break  # Found our response
                elif (
                    "method" in response
                    and response["method"].startswith("window/")
                    or response["method"].startswith("$/progress")
                ):
                    print(
                        f"[Main] Received notification/progress: {response.get('method')}",
                        file=sys.stderr,
                    )
                    # Handle or ignore progress/other notifications
                else:
                    print(
                        f"[Main] Received unexpected message while waiting for references: {response}",
                        file=sys.stderr,
                    )
                    # Decide if this is an error or just needs to be skipped

            if "error" in ref_response:
                print(f"Error finding references: {ref_response['error']}", file=sys.stderr)
            elif ref_response.get("result") is None:
                print("No references found (result is null).")
            elif not ref_response.get("result"):
                print("No references found (result is empty list).")
            else:
                print("\n--- References Found ---")
                for loc in ref_response["result"]:
                    uri = loc['uri']
                    start = loc['range']['start']
                    # Convert back to 1-based line/col for display
                    print(f"  File: {uri}")
                    print(f"  Line: {start['line'] + 1}, Column: {start['character'] + 1}")
                    print("-" * 10)
            print("--- End References ---")

        except queue.Empty:
            print(
                f"Error: Timeout waiting for references response after {RESPONSE_TIMEOUT}s",
                file=sys.stderr,
            )
            raise TimeoutError("Finding references failed")

    except Exception as e:
        print(f"\nAn error occurred: {e}", file=sys.stderr)

    finally:
        # 6. Shutdown sequence
        if process and process.poll() is None:  # Check if process is still running
            print("[Main] Initiating shutdown sequence...", file=sys.stderr)
            try:
                # Send Shutdown Request
                shutdown_id = request_id_counter
                request_id_counter += 1
                shutdown_request = {
                    "jsonrpc": "2.0",
                    "id": shutdown_id,
                    "method": "shutdown",
                    "params": None,
                }
                print(f"[Main] Sending Shutdown Request (ID: {shutdown_id})", file=sys.stderr)
                process.stdin.write(encode_message(shutdown_request))
                process.stdin.flush()

                # Wait for Shutdown Response (optional, but good practice)
                try:
                    while True:  # Consume any pending messages first
                        response = message_queue.get(
                            timeout=RESPONSE_TIMEOUT / 2
                        )  # Shorter timeout
                        if response.get("id") == shutdown_id:
                            print("[Main] Received Shutdown Response.", file=sys.stderr)
                            break
                        else:
                            print(
                                f"[Main] Consuming pending message during shutdown: {response.get('method', response.get('id'))}",
                                file=sys.stderr,
                            )
                except queue.Empty:
                    print(
                        "[Main] Warning: Timeout or no response waiting for shutdown confirmation.",
                        file=sys.stderr,
                    )

                # Send Exit Notification
                exit_notification = {"jsonrpc": "2.0", "method": "exit", "params": None}
                print("[Main] Sending Exit Notification", file=sys.stderr)
                process.stdin.write(encode_message(exit_notification))
                process.stdin.flush()

                # Give it a moment to exit cleanly
                try:
                    process.wait(timeout=2)
                    print("[Main] rust-analyzer process terminated cleanly.", file=sys.stderr)
                except subprocess.TimeoutExpired:
                    print(
                        "[Main] rust-analyzer did not exit after 'exit' notification, terminating forcefully.",
                        file=sys.stderr,
                    )
                    process.terminate()  # Force kill if needed
                    time.sleep(0.5)
                    if process.poll() is None:
                        process.kill()

            except (OSError, BrokenPipeError) as e:
                print(
                    f"[Main] Error during shutdown communication (process likely already exited): {e}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"[Main] Unexpected error during shutdown: {e}", file=sys.stderr)
                if process.poll() is None:
                    process.terminate()  # Ensure it's killed

        # Stop the reader thread
        if reader_thread and reader_thread.is_alive():
            print("[Main] Stopping reader thread...", file=sys.stderr)
            stop_reader.set()
            # Ensure the stream is closed to potentially unblock the reader's read() call
            if process and process.stdout:
                process.stdout.close()
            reader_thread.join(timeout=2)
            if reader_thread.is_alive():
                print("[Main] Warning: Reader thread did not stop gracefully.", file=sys.stderr)

        # Final check stderr
        if process:
            stderr_output = process.stderr.read()
            if stderr_output:
                print("\n--- Final rust-analyzer stderr ---", file=sys.stderr)
                print(stderr_output.decode('utf-8', errors='ignore'), file=sys.stderr)
                print("----------------------------------", file=sys.stderr)

        print("[Main] Script finished.", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Find references in a Rust file using rust-analyzer LSP."
    )
    parser.add_argument("file", help="Path to the Rust file.")
    parser.add_argument("line", type=int, help="Line number (1-based).")
    parser.add_argument("column", type=int, help="Column number (1-based).")
    args = parser.parse_args()

    main(args.file, args.line, args.column)
