pub mod app;

use anyhow::Result;

use crate::vault::model::Vault;
use app::App;

pub fn run_tui(vault: &Vault) -> Result<()> {
    let mut app = App::new(vault);
    app.run()
}
