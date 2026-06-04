//! LLM-powered local inference provider for semantic identifier renaming.
//!
//! Uses a local GGUF model via the [`mistralrs`] crate for constrained
//! chat-based inference to generate semantically meaningful identifier names.
//!
//! # Feature Gate
//!
//! This module requires the `smart-rename` Cargo feature. When enabled, the
//! [`LocalProvider`] loads a GGUF model and performs constrained inference
//! to suggest names based on extracted code context.
//!
//! # Model Requirements
//!
//! Any GGUF model with chat capabilities is compatible. Recommended models:
//! - Qwen 2.5/3.5 Coder series
//! - Codestral
//! - CodeLlama
//!
//! Smaller quantized models (Q4_0, Q4_K_M) provide acceptable quality
//! for identifier naming while being fast enough for batch renaming.

use std::sync::Mutex;

use mistralrs::{GgufModelBuilder, Model, RequestBuilder, StopTokens, TextMessageRole};
use tokio::runtime::Runtime;

use crate::{
    deobfuscation::renamer::{
        context::RenameContext, prompt, validate, RenameProvider, SmartRenameConfig,
    },
    Error, Result,
};

/// System prompt for identifier naming via chat API.
///
/// Instructs the model to respond with a single identifier name and no
/// additional text, ensuring that constrained decoding produces clean output.
const SYSTEM_PROMPT: &str = "\
You are a .NET identifier naming assistant. Given code context from a deobfuscated \
.NET assembly, suggest a single semantically meaningful identifier name. \
If the context says certain names are already taken, you MUST suggest a different name. \
Respond with ONLY the identifier name — no explanations, no punctuation, no quotes.";

/// LLM-powered rename provider using local GGUF model inference.
///
/// Performs constrained chat-based inference to generate semantically
/// meaningful identifier names. The model is loaded once during
/// [`initialize()`](RenameProvider::initialize) and reused for all
/// subsequent name suggestions.
///
/// # Thread Safety
///
/// The inference state is wrapped in a [`Mutex`] since model inference
/// is inherently sequential (GPU/CPU bound). The [`RenameProvider`] trait
/// requires `Send + Sync`, which `Mutex` satisfies.
pub struct LocalProvider {
    /// Configuration controlling model path, sampling, and constraints.
    config: SmartRenameConfig,
    /// Model and runtime — initialized lazily in `initialize()`.
    state: Mutex<Option<InferenceState>>,
}

/// Holds the loaded model and its async runtime.
///
/// The tokio runtime is created once and kept alive for the duration
/// of the provider's lifecycle. All inference calls block on this runtime.
struct InferenceState {
    /// The loaded GGUF model ready for inference.
    model: Model,
    /// Tokio runtime for driving async inference calls.
    runtime: Runtime,
}

impl LocalProvider {
    /// Creates a new local provider with the given configuration.
    ///
    /// The model is not loaded until [`initialize()`](RenameProvider::initialize)
    /// is called. This allows the provider to be constructed cheaply and
    /// initialized only when actually needed.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration specifying model path, sampling parameters,
    ///   and constraint patterns.
    pub fn new(config: SmartRenameConfig) -> Self {
        Self {
            config,
            state: Mutex::new(None),
        }
    }

    /// Builds a user prompt from a rename context for chat-based inference.
    ///
    /// Converts the FIM-style prompt from [`prompt::build_fim_prompt`] into
    /// a chat-compatible format by replacing FIM tokens with a `???`
    /// placeholder and natural language framing.
    ///
    /// # Arguments
    ///
    /// * `context` - The rename context with extracted features.
    ///
    /// # Returns
    ///
    /// A user message string for the chat request.
    fn build_chat_prompt(&self, context: &RenameContext) -> String {
        let (prefix, suffix) = prompt::build_fim_prompt(context, self.config.max_phases_in_prompt);

        // Strip FIM tokens and combine into a chat prompt
        let clean_prefix = prefix
            .replace("<|fim_prefix|>", "")
            .replace("<|fim_suffix|>", "");
        let clean_suffix = suffix.replace("<|fim_middle|>", "");

        let prompt = format!(
            "Suggest a name for the identifier marked with ??? in this .NET code:\n\n\
             {clean_prefix}???{clean_suffix}"
        );

        log::debug!("Chat prompt:\n{prompt}");

        prompt
    }

    /// Performs a single inference call to generate an identifier name.
    ///
    /// Sends a chat request to the loaded model with:
    /// - A system prompt establishing the naming task
    /// - A user prompt containing the code context with a `???` placeholder
    /// - Stop sequences preventing generation beyond the name
    ///
    /// Post-generation validation (PascalCase/camelCase enforcement,
    /// keyword rejection, length limits) is handled by
    /// [`validate::validate_name()`] in the caller.
    ///
    /// # Arguments
    ///
    /// * `state` - The initialized inference state with model and runtime.
    /// * `context` - The rename context with extracted features.
    ///
    /// # Returns
    ///
    /// The generated name trimmed of whitespace, or `None` if inference
    /// produces an empty result.
    ///
    /// # Errors
    ///
    /// Returns an error if the model inference call fails.
    fn infer(&self, state: &InferenceState, context: &RenameContext) -> Result<Option<String>> {
        let user_prompt = self.build_chat_prompt(context);
        let stop_seqs = self.config.stop_sequences.clone();
        let max_tokens = self.config.max_tokens as usize;
        let temperature = self.config.temperature;

        let request = RequestBuilder::new()
            .add_message(TextMessageRole::System, SYSTEM_PROMPT)
            .add_message(TextMessageRole::User, user_prompt)
            .set_sampler_max_len(max_tokens)
            .set_sampler_temperature(temperature)
            .set_sampler_stop_toks(StopTokens::Seqs(stop_seqs));

        let response = state
            .runtime
            .block_on(state.model.send_chat_request(request))
            .map_err(|e| Error::Deobfuscation(format!("Model inference failed: {e}")))?;

        if let Some(choice) = response.choices.first() {
            log::debug!(
                "Model response: content={:?} finish_reason={:?}",
                choice.message.content,
                choice.finish_reason
            );
        }

        let generated = response
            .choices
            .first()
            .and_then(|c| c.message.content.as_deref())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(generated)
    }
}

impl RenameProvider for LocalProvider {
    /// Returns the provider name for logging and diagnostics.
    fn name(&self) -> &'static str {
        "LocalProvider"
    }

    /// Initializes the provider by loading the GGUF model.
    ///
    /// Creates a tokio runtime and uses [`GgufModelBuilder`] to load the
    /// model specified in the configuration. The model remains loaded until
    /// [`shutdown()`](RenameProvider::shutdown) is called.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The model file does not exist at the configured path
    /// - The GGUF model cannot be loaded (corrupt file, unsupported format)
    /// - The tokio runtime cannot be created
    fn initialize(&mut self) -> Result<()> {
        if !self.config.model_path.exists() {
            return Err(Error::Deobfuscation(format!(
                "Smart rename model not found: {}",
                self.config.model_path.display()
            )));
        }

        let runtime = Runtime::new()
            .map_err(|e| Error::Deobfuscation(format!("Failed to create tokio runtime: {e}")))?;

        let model_path = self.config.model_path.canonicalize().map_err(|e| {
            Error::Deobfuscation(format!(
                "Failed to resolve model path {}: {e}",
                self.config.model_path.display()
            ))
        })?;
        let parent = model_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let filename = model_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("model.gguf")
            .to_string();

        let force_cpu = self.config.force_cpu;

        let model = runtime.block_on(async {
            let mut builder = GgufModelBuilder::new(parent.display().to_string(), vec![filename]);

            if force_cpu {
                builder = builder.with_force_cpu();
            }

            builder
                .build()
                .await
                .map_err(|e| Error::Deobfuscation(format!("Model load failed: {e}")))
        })?;

        log::info!(
            "Smart rename model loaded: {}",
            self.config.model_path.display()
        );

        let mut guard = self
            .state
            .lock()
            .map_err(|e| Error::Deobfuscation(format!("Smart rename state mutex poisoned: {e}")))?;
        *guard = Some(InferenceState { model, runtime });
        Ok(())
    }

    /// Suggests a name for one identifier using LLM inference.
    ///
    /// Builds a chat prompt from the rename context, sends it to the model
    /// with constrained decoding, and validates the result.
    ///
    /// # Arguments
    ///
    /// * `context` - The extracted features for the identifier.
    ///
    /// # Returns
    ///
    /// A validated identifier name, or `None` if:
    /// - The provider is not initialized
    /// - The context lacks an [`IdentifierKind`]
    /// - Inference produces an invalid or empty result
    ///
    /// # Errors
    ///
    /// Returns an error if model inference fails unexpectedly.
    fn suggest_name(&self, context: &RenameContext) -> Result<Option<String>> {
        let kind = match context.kind {
            Some(k) => k,
            None => return Ok(None),
        };

        let guard = self
            .state
            .lock()
            .map_err(|e| Error::Deobfuscation(format!("Smart rename state mutex poisoned: {e}")))?;
        let Some(ref state) = *guard else {
            return Ok(None);
        };

        let raw_name = self.infer(state, context)?;

        match raw_name {
            Some(name) => Ok(validate::validate_name(
                &name,
                kind,
                self.config.max_name_length,
            )),
            None => Ok(None),
        }
    }

    /// Shuts down the provider by unloading the model.
    ///
    /// Drops the model and tokio runtime to release all resources
    /// (memory, GPU allocations). The provider can be re-initialized
    /// after shutdown if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal state mutex has been poisoned.
    fn shutdown(&mut self) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| Error::Deobfuscation(format!("Smart rename state mutex poisoned: {e}")))?;
        *guard = None;
        log::info!("Smart rename model unloaded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscation::renamer::{
        context::{IdentifierKind, RenameContext},
        providers::local::LocalProvider,
        RenameProvider, SmartRenameConfig,
    };

    use std::path::PathBuf;

    #[test]
    fn test_local_provider_config() {
        let config = SmartRenameConfig {
            model_path: PathBuf::from("/nonexistent/model.gguf"),
            max_tokens: 20,
            threads: 4,
            force_cpu: false,
            ..SmartRenameConfig::default()
        };
        let provider = LocalProvider::new(config);
        assert_eq!(provider.name(), "LocalProvider");
    }

    #[test]
    fn test_local_provider_uninitialized_returns_none() {
        let config = SmartRenameConfig::default();
        let provider = LocalProvider::new(config);

        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            ..Default::default()
        };

        // Without initialization, should return None
        let result = provider.suggest_name(&ctx).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_local_provider_no_kind_returns_none() {
        let config = SmartRenameConfig::default();
        let provider = LocalProvider::new(config);

        let ctx = RenameContext::default();
        let result = provider.suggest_name(&ctx).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_local_provider_missing_model_file() {
        let config = SmartRenameConfig {
            model_path: PathBuf::from("/nonexistent/model.gguf"),
            ..SmartRenameConfig::default()
        };
        let mut provider = LocalProvider::new(config);
        let result = provider.initialize();
        assert!(result.is_err(), "Should fail with missing model file");
    }

    #[test]
    fn test_chat_prompt_construction() {
        let config = SmartRenameConfig::default();
        let provider = LocalProvider::new(config);

        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            dotnet_type: Some("void".to_string()),
            call_site_skeleton: Some("    File.WriteAllText(var_0, var_1);".to_string()),
            ..Default::default()
        };

        let prompt = provider.build_chat_prompt(&ctx);
        assert!(prompt.contains("???"), "Should contain placeholder");
        assert!(
            prompt.contains("File.WriteAllText"),
            "Should contain call target"
        );
        assert!(
            !prompt.contains("<|fim_prefix|>"),
            "Should not contain FIM tokens"
        );
        assert!(
            !prompt.contains("<|fim_middle|>"),
            "Should not contain FIM tokens"
        );
    }

    /// Integration test: requires a GGUF model file.
    /// Set DOTSCOPE_SMART_RENAME_MODEL=/path/to/model.gguf to run.
    #[test]
    #[ignore]
    fn test_local_provider_inference() {
        let model_path = match std::env::var("DOTSCOPE_SMART_RENAME_MODEL") {
            Ok(p) => PathBuf::from(p),
            Err(_) => {
                eprintln!("Skipping: DOTSCOPE_SMART_RENAME_MODEL not set");
                return;
            }
        };

        let config = SmartRenameConfig {
            model_path,
            max_tokens: 20,
            threads: 0,
            force_cpu: false,
            ..SmartRenameConfig::default()
        };

        let mut provider = LocalProvider::new(config);
        provider.initialize().unwrap();

        let ctx = RenameContext {
            kind: Some(IdentifierKind::Method),
            call_targets: vec![
                "System.IO.File::ReadAllText".to_string(),
                "System.Text.Encoding::GetBytes".to_string(),
            ],
            dotnet_type: Some("byte[]".to_string()),
            ..Default::default()
        };

        let name = provider.suggest_name(&ctx).unwrap();
        eprintln!("Generated name: {name:?}");
        assert!(name.is_some(), "Model should produce a name");

        let name = name.unwrap();
        assert!(
            name.chars().next().unwrap().is_ascii_uppercase(),
            "Method name '{name}' should be PascalCase"
        );

        provider.shutdown().unwrap();
    }
}
