use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long, help = "指定某函数在shellcode头部")]
    pub head: Option<String>,
    #[arg(short, long, help = "输入文件路径")]
    pub input: String,
    #[arg(short, long, help = "输出文件路径")]
    pub output: Option<String>,
    #[arg(
        short,
        long,
        default_value = "false",
        help = "完全体shellcode data和code分离"
    )]
    pub mega: bool,
    #[arg(short, long, default_value = "shellcode", help = "cpp的namespace名称")]
    pub namespace: String,
    #[arg(short, long, default_value = "false", help = "是否对shellcode进行对齐")]
    pub align: bool,
}
