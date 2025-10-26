#![allow(dead_code)]

mod cli;
mod commands;
mod config;
mod crypto;
mod error;
mod pgp;
mod tui;
mod util;
mod vault;

use anyhow::Result;
use clap::Parser;
