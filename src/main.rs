use crate::scale::Shellcode;
use clap::Parser;
use tracing_subscriber::fmt::time::LocalTime;
use args::Args;
mod scale;
mod args;



fn main() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_target(false)
        .with_timer(LocalTime::rfc_3339())
        .init();

    let args = Args::parse();
    tracing::info!("输入文件: {}", args.input);
    tracing::info!("输出文件: {}", args.output);
    tracing::info!("命名空间: {}", args.namespace);
    if let Some(head) = &args.head {
        tracing::info!("首函数: {}", head);
    }
    let mut shellcode = Shellcode::new(args);
    match shellcode.gen() {
        Ok(_) => tracing::info!("生成成功"),
        Err(e) => tracing::error!("生成失败: {}", e),
    }
}
