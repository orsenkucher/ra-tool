//! # Message Processing System Example
//!
//! This crate demonstrates a simple system for processing different types of messages
//! using traits, generics, enums, and macros. It's designed to be interesting
//! to explore with rust-analyzer.

pub mod processing; // Import the processing module

use crate::processing::MessageHandler;
use std::fmt::Debug;

/// A simple logging macro.
#[macro_export] // Make macro available outside its definition scope
macro_rules! log_processing {
    ($handler_expr:expr, $message_expr:expr) => {{
        // Use a block to scope variables and return the result
        let handler = $handler_expr; // Evaluate expressions once
        let message = $message_expr;
        println!("\nAttempting to process: {:?}", message);
        let result = handler.handle(message); // The actual call
        match &result {
            Ok(summary) => println!("✅ Success: {}", summary),
            Err(e) => println!("❌ Failed: {}", e),
        }
        result // Return the result from the macro invocation
    }};
}

/// Generic function to run any handler with its message type.
/// Demonstrates using the trait bound.
fn run_handler<H, M>(handler: &H, message: M) -> Result<String, processing::ProcessingError>
where
    H: processing::MessageHandler<M>,
    M: Debug + Clone, // Clone needed for the log_processing macro reuse
{
    println!("--- Running via generic function ---");
    // Note: log_processing! takes ownership, so we clone here if needed outside
    log_processing!(handler, message.clone())
}

fn main() {
    println!("== Message Processing System Startup ==");

    // Create handlers
    let text_handler = processing::TextMessageHandler::default();
    let command_handler = processing::CommandMessageHandler {
        supported_range: 100..200,
    };

    // Create messages
    let msg1 = processing::TextMessage {
        sender: "Alice".to_string(),
        content: "Hello Bob, let's sync up later.".to_string(),
    };
    let msg2 = processing::TextMessage {
        sender: "Bob".to_string(),
        content: "".to_string(), // Invalid message
    };
    let msg3 = processing::TextMessage {
        sender: "Charlie".to_string(),
        content: "This is URGENT!".to_string(), // Simulates resource error
    };

    let cmd1 = processing::CommandMessage {
        command_id: 150,
        payload: 42,
    };
    let cmd2 = processing::CommandMessage {
        command_id: 99,
        payload: 10,
    }; // Invalid ID
    let cmd3 = processing::CommandMessage {
        command_id: 110,
        payload: -5,
    }; // Internal error

    // Process messages using the macro directly
    println!("\n=== Direct Macro Processing ===");
    let _res1 = log_processing!(&text_handler, msg1.clone()); // Clone because msg1 is used later
    let _res2 = log_processing!(&text_handler, msg2);
    let _res3 = log_processing!(&text_handler, msg3);

    let _res4 = log_processing!(&command_handler, cmd1);
    let _res5 = log_processing!(&command_handler, cmd2);
    let _res6 = log_processing!(&command_handler, cmd3);

    // Process messages using the generic function
    println!("\n=== Generic Function Processing ===");
    let _res7 = run_handler(&text_handler, msg1); // msg1 was cloned before
    let _res8 = run_handler(&command_handler, cmd1);

    // You can inspect the final state (though atomics are tricky without more sync)
    // let final_text_count = text_handler.processed_count.load(std::sync::atomic::Ordering::Relaxed);
    // println!("\nFinal text messages processed (approx): {}", final_text_count);

    println!("\n== System Shutdown ==");
}

// --- Things to try with rust-analyzer CLI ---
// (Assuming you save this as src/main.rs in a cargo project)
//
// 1. Build/Check:
//    cargo check
//
// 2. Hover:
//    rust-analyzer hover --file src/main.rs --line <line_no> --column <col_no>
//    (Try hovering over `ProcessingError`, `MessageHandler`, `handle`, `text_handler`, `log_processing!`, `run_handler`)
//
// 3. Goto Definition:
//    rust-analyzer goto-definition --file src/main.rs --line <line_no> --column <col_no>
//    (Try on `processing::TextMessage`, `handle` inside `log_processing!`, `MessageHandler` trait bound in `run_handler`)
//
// 4. Find References / Implementations:
//    rust-analyzer find-all-refs --file src/main.rs --line <line_no> --column <col_no>
//    (Try on `TextMessage`, `ProcessingError`)
//    rust-analyzer related-symbols --file src/processing.rs --line <line_no_of_trait> --column <col_no_of_trait>
//    (Run on the `MessageHandler` trait definition line in processing.rs if you split the file - or adjust path/line)
//    (Alternative: `implementations` might be a subcommand depending on version/fork)
//
// 5. Expand Macro:
//    rust-analyzer expand-macro --file src/main.rs --line <line_no> --column <col_no>
//    (Try on one of the `log_processing!` calls in `main`)
//
// 6. View Hir / Syntax Tree (Advanced):
//    rust-analyzer view-hir --file src/main.rs --line <line_no> --column <col_no>
//    rust-analyzer syntax-tree --file src/main.rs
//
// 7. Inlay Hints (if supported by CLI version or via LSP client):
//    (Shows inferred types, parameter names etc.)
//
// 8. Diagnostics:
//    Introduce an error (e.g., type mismatch, missing field) and run `cargo check`.
//    rust-analyzer diagnostics --file src/main.rs
//
