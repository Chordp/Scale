use crate::scale::Shellcode;
use args::Args;
use clap::Parser;
use tracing_subscriber::fmt::time::LocalTime;
mod args;
mod scale;
mod utils;

fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_ansi(true)
        .with_target(false)
        .with_timer(LocalTime::rfc_3339())
        .init();
    if cfg!(target_os = "windows") {
        utils::enable_ansi_support()?;
    }
    let args = Args::parse();
    tracing::info!("输入文件: {}", args.input);
    tracing::info!("输出文件: {}", args.output.as_ref().unwrap_or(&args.input));
    tracing::info!("命名空间: {}", args.namespace);
    if let Some(head) = &args.head {
        tracing::info!("首函数: {}", head);
    }
    let mut shellcode = Shellcode::new(args);
    match shellcode.gen() {
        Ok(_) => tracing::info!("生成成功"),
        Err(e) => tracing::error!("生成失败: {}", e),
    }
    Ok(())
}
