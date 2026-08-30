//! Deterministic fuzz-style regression tests for untrusted text inputs.
//!
//! This is intentionally dependency-light so it runs in the normal CI suite.
//! It exercises randomized Unicode, punctuation, and malformed PoW values and
//! asserts that parser and search boundaries return safely without panicking.

use rand::{rngs::StdRng, Rng, SeedableRng};
use veil_forum::{markdown, pow, store::Store};

fn hostile_inputs() -> Vec<String> {
    let mut rng = StdRng::seed_from_u64(0x7665_696c_5f66_757a);
    let alphabet = [
        'a', '中', '😀', '\0', '\n', '\r', '\'', '"', '<', '>', '&', '/', '\\', '*', '%', '_', '-',
        '(', ')', '[', ']', '{', '}', ';', '\u{202e}',
    ];
    let mut inputs = vec![
        String::new(),
        " ".repeat(4096),
        "\0<script>alert(1)</script>![x](https://example.test/x)".to_string(),
        "\" OR 1=1 --".to_string(),
        "*".repeat(8_192),
        "中".repeat(2_048),
    ];
    for _ in 0..256 {
        let len = rng.gen_range(0..512);
        let value = (0..len)
            .map(|_| alphabet[rng.gen_range(0..alphabet.len())])
            .collect();
        inputs.push(value);
    }
    inputs
}

#[tokio::test]
async fn randomized_markdown_search_and_pow_inputs_fail_safely() -> anyhow::Result<()> {
    let store = Store::open(":memory:").await?;
    let manager = pow::Manager::new(store.clone());

    for input in hostile_inputs() {
        let html = markdown::render(&input);
        assert!(!html.contains("<script"));
        assert!(!html.contains("https://example.test/x"));

        // Search input is passed through both the FTS quoting and short-query
        // LIKE fallback paths. Either no result or a normal result is valid.
        let _ = store.search_posts(&input, 0, 100_000).await?;

        // Arbitrary malformed client PoW data must be a normal rejection, not a
        // panic or an accepted proof. A one-second-old expiry also avoids any
        // accidental success if random fields happen to line up.
        assert!(manager
            .verify(pow::Scope::Post, &input, &input, 99, 0, &input, &input)
            .await
            .is_err());
    }
    Ok(())
}
