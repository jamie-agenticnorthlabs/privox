// Optional NER client — sends text to a local Ollama endpoint for contextual
// entity detection. Only active when [detection.ner] enabled = true in config.
// If the NER endpoint is unavailable, detection degrades gracefully to regex-only.
// TODO(next-session): Implement NER client after regex detector is complete.
