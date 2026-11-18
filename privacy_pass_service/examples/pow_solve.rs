//! This test client reads a challenge as JSON from stdin and prints a solution in the widget's format.
use altcha::{solve_challenge, Challenge, Payload, SolveChallengeOptions};
use base64ct::{Base64, Encoding};
use std::io::{self, Read, Write};

fn solve() -> anyhow::Result<()> {
    let mut input = String::new();
    io::stdin().take(8193).read_to_string(&mut input)?;
    anyhow::ensure!(input.len() <= 8192, "challenge too large");
    let challenge: Challenge = serde_json::from_str(&input)?;
    let solution = solve_challenge(SolveChallengeOptions::new(&challenge))?
        .ok_or_else(|| anyhow::anyhow!("solve timed out"))?;
    let payload = Payload {
        challenge,
        solution,
    };
    let encoded = Base64::encode_string(&serde_json::to_vec(&payload)?);
    writeln!(io::stdout().lock(), "{encoded}")?;
    Ok(())
}

fn main() {
    if solve().is_err() {
        // Report a generic error to keep the challenge and solution out of diagnostics.
        eprintln!("PoW solving failed");
        std::process::exit(1);
    }
}
