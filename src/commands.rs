use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode{
        #[clap(long="strict", short='s')]
        strict: bool,
        #[clap(long="all", short='a')]
        all: bool
    },
}
