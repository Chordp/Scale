use crate::scale::Shellcode;
use clap::Parser;
use std::fs;
use std::io::Write;
use std::path::Path;
use tracing_subscriber::fmt::time::LocalTime;

mod scale;
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    head: Option<String>,
    #[arg(short, long)]
    input: String,
    #[arg(short, long, default_value = "shellcode.h")]
    output: String,
    #[arg(short, long, default_value = "shellcode")]
    namespace: String,
    #[arg(short, long, default_value = "false")]
    bin: bool,
}
fn shellcode_gen(args: Args) -> scale::Result<()> {
    let file = fs::read(args.input)?;
    let mut shell = Shellcode::default();
    shell.form_binary(&file)?;
    match args.head {
        None => shell.parse()?,
        Some(head) => shell.parse_head(&head)?,
    }
    let shellcode = shell.gen_cpp(&args.namespace)?;
    let mut file = fs::File::create(&args.output)?;

    file.write_all(shellcode.as_bytes())?;

    if args.bin {
        // 修改output 后缀为 bin
        let mut output = Path::new(&args.output).to_path_buf();
        output.set_extension("bin");
        let mut file = fs::File::create(output)?;
        file.write_all(&shell.code)?;
    }
    Ok(())
}
fn main() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_timer(LocalTime::rfc_3339())
        .init();

    let args = Args::parse();
    tracing::info!("输入文件: {}", args.input);
    tracing::info!("输出文件: {}", args.output);
    tracing::info!("命名空间: {}", args.namespace);
    if let Some(head) = &args.head {
        tracing::info!("首函数: {}", head);
    }
    match shellcode_gen(args) {
        Ok(_) => tracing::info!("生成成功"),
        Err(e) => tracing::error!("生成失败: {}", e),
    }
}
