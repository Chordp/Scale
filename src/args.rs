use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub head: Option<String>,
    #[arg(short, long)]
    pub input: String,
    #[arg(short, long)]
    pub output: Option<String>,
    #[arg(short, long, default_value = "shellcode")]
    pub namespace: String,
    #[arg(short, long, default_value = "false")]
    pub align: bool,
}
