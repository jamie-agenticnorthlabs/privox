//! `privox` — Privacy proxy for LLM calls.
//!
//! CLI parsing, config loading, vault initialization, and server startup.
//! No business logic lives here; this module wires together the subsystems.
//
// SCAFFOLDING: allow dead_code and unused_imports until all modules are connected to main.
// Remove these attributes when server.rs and the pipeline are wired up.
#![allow(dead_code, unused_imports)]

mod config;
mod detector;
mod detokenizer;
mod error;
mod proxy;
mod server;
mod tokenizer;
mod types;
mod vault;

fn main() {
    // TODO(next-session): Replace with full startup sequence using clap + tokio.
    println!("privox starting — not yet implemented");
}
