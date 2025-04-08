// Define a module for our core processing logic
use std::fmt::{self, Debug, Display};

/// Represents different kinds of errors that can occur during processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessingError {
    InvalidFormat(String),
    ResourceUnavailable(String),
    InternalError(String),
}

// Implement Display for nice error messages
impl Display for ProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessingError::InvalidFormat(msg) => write!(f, "Invalid Format: {}", msg),
            ProcessingError::ResourceUnavailable(res) => {
                write!(f, "Resource '{}' unavailable", res)
            }
            ProcessingError::InternalError(desc) => {
                write!(f, "Internal Processor Error: {}", desc)
            }
        }
    }
}

// Make it usable as a standard Error
impl std::error::Error for ProcessingError {}

/// A trait defining a message handler.
/// It's generic over the type of message `M` it can handle.
pub trait MessageHandler<M>
where
    M: Debug,
{
    /// Processes a single message.
    /// Returns a String summarizing the result on success, or a ProcessingError on failure.
    fn handle(&self, message: M) -> Result<String, ProcessingError>;
}

// --- Concrete Message Types ---

/// Represents a text message.
#[derive(Debug, Clone)]
pub struct TextMessage {
    pub sender: String,
    pub content: String,
}

/// Represents a numerical command.
#[derive(Debug, Clone, Copy)] // Note: Copy requires all fields to be Copy
pub struct CommandMessage {
    pub command_id: u32,
    pub payload: i64,
}

// --- Concrete Handlers ---

/// A handler specifically for TextMessages.
#[derive(Debug, Default)] // Default requires no special setup
pub struct TextMessageHandler {
    processed_count: std::sync::atomic::AtomicUsize, // Use atomic for interior mutability demo
}

impl MessageHandler<TextMessage> for TextMessageHandler {
    fn handle(&self, message: TextMessage) -> Result<String, ProcessingError> {
        // Increment count - needs Ordering
        self.processed_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("-> Handling TextMessage from '{}'", message.sender);
        if message.content.is_empty() {
            Err(ProcessingError::InvalidFormat(
                "Message content cannot be empty".to_string(),
            ))
        } else if message.content.to_lowercase().contains("urgent") {
            // Simulate a resource issue for "urgent" messages
            Err(ProcessingError::ResourceUnavailable(
                "Priority Queue".to_string(),
            ))
        } else {
            Ok(format!(
                "Processed text: '{}...'",
                message.content.chars().take(10).collect::<String>()
            ))
        }
    }
}

/// A handler specifically for CommandMessages.
#[derive(Debug, Clone)] // Clone needed if we want multiple instances easily
pub struct CommandMessageHandler {
    pub supported_range: std::ops::Range<u32>,
}

impl MessageHandler<CommandMessage> for CommandMessageHandler {
    fn handle(&self, message: CommandMessage) -> Result<String, ProcessingError> {
        println!("-> Handling CommandMessage ID: {}", message.command_id);
        if !self.supported_range.contains(&message.command_id) {
            Err(ProcessingError::InvalidFormat(format!(
                "Command ID {} out of supported range {:?}",
                message.command_id, self.supported_range
            )))
        } else if message.payload < 0 {
            // Simulate an internal error
            Err(ProcessingError::InternalError(
                "Negative payloads not supported yet".to_string(),
            ))
        } else {
            // Simulate some work based on payload
            let result_value = message.payload.pow(2);
            Ok(format!(
                "Executed command {}: result = {}",
                message.command_id, result_value
            ))
        }
    }
}
