//! `pouw`, the command line tool of PoUW-ZK: keys, signed transactions and ids, built
//! offline with the same code the node uses. Output goes to stdout as JSON or hex, so
//! it pipes into `curl` against the node API.

use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Parser, Subcommand, ValueEnum};
use pouw_crypto::{Address, ParseError, SigningKey, text};
use pouw_light_client::{Wallet, WalletError};
use pouw_types::{Amount, ChainId, Nonce, SignedTx, SpecError, genesis_id, parse_chain_spec, txid};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(name = "pouw", version, about = "Command line tool of PoUW-ZK")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Draws a new key and prints its seed and address.
    Keygen,
    /// Prints the address of a seed.
    Address {
        /// 64 hex digits.
        seed: String,
    },
    /// Signs a transfer.
    Transfer {
        /// Seed of the sender, 64 hex digits.
        #[arg(long)]
        seed: String,
        /// Chain id of the network.
        #[arg(long)]
        chain_id: u32,
        /// Nonce of the sender's account.
        #[arg(long)]
        nonce: u64,
        /// Receiver, `addr:` and 64 hex digits.
        #[arg(long)]
        to: Address,
        /// Coins moved.
        #[arg(long)]
        amount: u64,
        /// Fee for the miner.
        #[arg(long)]
        fee: u64,
        /// `json` for `Content-Type: application/json`, `borsh` for hex of the bytes.
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
    },
    /// Prints the txid of a signed transaction given as hex of its borsh bytes.
    Txid {
        /// Hex of the borsh bytes of a `SignedTx`.
        borsh_hex: String,
    },
    /// Prints the genesis id of a chain spec file. The id in the file is not compared,
    /// so the output is the value for `expected_genesis_id` of a new spec.
    GenesisId {
        /// Path of the chain spec JSON.
        spec: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Json,
    Borsh,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("bad seed: {0}")]
    Seed(#[from] ParseError),
    #[error("bad hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("not a borsh SignedTx: {0}")]
    Borsh(io::Error),
    #[error("cannot encode: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot sign: {0}")]
    Wallet(#[from] WalletError),
    #[error("cannot read the chain spec {path}: {source}")]
    ReadSpec { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error("cannot write: {0}")]
    Output(#[from] io::Error),
}

fn seed(text_form: &str) -> Result<SigningKey, CliError> {
    Ok(SigningKey::from_seed(text::decode_fixed(text_form)?))
}

fn run(command: Command, out: &mut impl Write) -> Result<(), CliError> {
    match command {
        Command::Keygen => {
            let key = SigningKey::generate();
            let json = serde_json::json!({
                "seed": hex::encode(key.seed()),
                "address": key.address(),
            });
            writeln!(out, "{json}")?;
        }
        Command::Address { seed: text_form } => {
            writeln!(out, "{}", seed(&text_form)?.address())?;
        }
        Command::Transfer {
            seed: text_form,
            chain_id,
            nonce,
            to,
            amount,
            fee,
            format,
        } => {
            let mut wallet = Wallet::new(seed(&text_form)?, ChainId(chain_id), Nonce(nonce));
            let tx = wallet.transfer(to, Amount(amount), Amount(fee))?;
            match format {
                Format::Json => writeln!(out, "{}", serde_json::to_string(&tx)?)?,
                Format::Borsh => writeln!(out, "{}", hex::encode(borsh::to_vec(&tx)?))?,
            }
        }
        Command::Txid { borsh_hex } => {
            let bytes = hex::decode(borsh_hex.trim())?;
            let tx: SignedTx = borsh::from_slice(&bytes).map_err(CliError::Borsh)?;
            writeln!(out, "{}", txid(&tx))?;
        }
        Command::GenesisId { spec } => {
            let json = fs::read_to_string(&spec).map_err(|source| CliError::ReadSpec {
                path: spec.clone(),
                source,
            })?;
            writeln!(out, "{}", genesis_id(&parse_chain_spec(&json)?))?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => match writeln!(io::stderr(), "error: {error}") {
            Ok(()) => ExitCode::FAILURE,
            Err(_) => ExitCode::from(2),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(command: Command) -> String {
        let mut out = Vec::new();
        run(command, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn transfer_matches_the_test_vector_of_block_md() {
        let transfer = |format| Command::Transfer {
            seed: SEED.to_owned(),
            chain_id: 1,
            nonce: 0,
            to: Address([0x22; 32]),
            amount: 1000,
            fee: 10,
            format,
        };
        let borsh_hex = output(transfer(Format::Borsh));
        let id = output(Command::Txid {
            borsh_hex: borsh_hex.clone(),
        });
        assert_eq!(
            id.trim(),
            "tx:41ef667fcdab0af9fbf57805b90f90a60825c43d4a796b1f26980207e622e6f7"
        );
        let json: serde_json::Value =
            serde_json::from_str(&output(transfer(Format::Json))).unwrap();
        assert_eq!(json["body"]["kind"], "transfer");
    }

    #[test]
    fn transfer_with_the_last_nonce_is_refused() {
        let command = Command::Transfer {
            seed: SEED.to_owned(),
            chain_id: 1,
            nonce: u64::MAX,
            to: Address([0x22; 32]),
            amount: 1000,
            fee: 10,
            format: Format::Json,
        };
        let error = run(command, &mut Vec::new()).unwrap_err();
        assert!(matches!(
            error,
            CliError::Wallet(WalletError::NonceExhausted)
        ));
    }

    #[test]
    fn address_of_the_test_seed() {
        assert_eq!(
            output(Command::Address {
                seed: SEED.to_owned()
            })
            .trim(),
            "addr:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
    }

    #[test]
    fn genesis_id_of_the_devnet_spec_is_the_expected_id() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../chainspec/devnet.json");
        let expected = parse_chain_spec(&fs::read_to_string(&path).unwrap())
            .unwrap()
            .expected_genesis_id;
        let printed = output(Command::GenesisId { spec: path });
        assert_eq!(printed.trim(), expected.to_string());
    }

    #[test]
    fn the_command_line_is_consistent() {
        <Cli as clap::CommandFactory>::command().debug_assert();
    }
}
