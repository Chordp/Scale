use clap::Parser;
use scale::{Config, Shellcode, ShellcodeOutput};
use std::fs;
use std::io::Write;
use std::path::Path;
use color_eyre::eyre::eyre;
use tracing_subscriber::fmt::time::LocalTime;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, help = "指定某函数在shellcode头部")]
    head: Option<String>,
    #[arg(short, long, help = "输入文件路径")]
    input: String,
    #[arg(short, long, help = "输出文件路径")]
    output: Option<String>,
    #[arg(short, long, default_value = "false", help = "完全体shellcode data和code分离")]
    mega: bool,
    #[arg(short, long, default_value = "shellcode", help = "cpp的namespace名称")]
    namespace: String,
    #[arg(short, long, default_value = "false", help = "是否对shellcode进行对齐")]
    align: bool,
}

#[cfg(target_os = "windows")]
fn enable_ansi_support() -> color_eyre::Result<()> {
    use windows::core::w;
    use windows::Win32::Foundation::{GetLastError, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{GetConsoleMode, SetConsoleMode, CONSOLE_MODE};

    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    unsafe {
        let console_handle = CreateFileW(
            w!("CONOUT$"),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES::default(),
            None,
        )?;
        if console_handle == INVALID_HANDLE_VALUE {
            GetLastError().ok()?;
        }
        let mut console_mode = CONSOLE_MODE::default();
        GetConsoleMode(console_handle, &mut console_mode)?;
        if console_mode.0 & ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
            SetConsoleMode(
                console_handle,
                CONSOLE_MODE(console_mode.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING),
            )?;
        }
    }
    Ok(())
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    // 初始化日志
    tracing_subscriber::fmt()
        .with_ansi(true)
        .with_target(false)
        .with_timer(LocalTime::rfc_3339())
        .init();

    #[cfg(target_os = "windows")]
    enable_ansi_support()?;

    let args = Args::parse();
    tracing::info!("输入文件: {}", args.input);
    tracing::info!("输出文件: {}", args.output.as_ref().unwrap_or(&args.input));
    tracing::info!("命名空间: {}", args.namespace);
    if let Some(head) = &args.head {
        tracing::info!("首函数: {}", head);
    }

    // 将 CLI 参数转换为 Config
    let config = Config::new().with_mega(args.mega).with_align(args.align);
    let config = match &args.head {
        Some(head) => config.with_head(head),
        None => config,
    };

    // 读取输入文件
    let binary = fs::read(&args.input)?;

    // 处理 shellcode
    let mut shellcode = Shellcode::new(config);
    let output = shellcode.make(&binary)?;

    // 写入输出文件
    let output_path = Path::new(args.output.as_ref().unwrap_or(&args.input));
    write_output(&output, output_path, &args.namespace)?;

    tracing::info!("生成成功");
    Ok(())
}

fn write_output(output: &ShellcodeOutput, path: &Path, namespace: &str) -> color_eyre::Result<()> {
    let mut path = path.to_path_buf();

    // 写入 .bin 文件
    path.set_extension("bin");
    let mut file = fs::File::create(&path)?;
    file.write_all(&output.payload)?;

    // 生成并写入 .hpp 文件
    let cpp = gen_cpp(output, namespace);
    path.set_extension("hpp");
    let mut file = fs::File::create(&path)?;
    file.write_all(cpp.as_bytes())?;

    // 生成并写入 .rs 文件
    let bin_name = path
        .with_extension("bin")
        .file_name()
        .ok_or(eyre!("获取文件名失败!"))?
        .to_string_lossy()
        .to_string();
    let rs = gen_rs(output, &bin_name);
    path.set_extension("rs");
    let mut file = fs::File::create(&path)?;
    file.write_all(rs.as_bytes())?;

    // 生成并写入 .json 文件
    let json = serde_json::to_string(output)?;
    path.set_extension("json");
    let mut file = fs::File::create(&path)?;
    file.write_all(json.as_bytes())?;

    // 生成并写入 .yaml 文件
    let yaml = serde_yaml::to_string(output)?;
    path.set_extension("yaml");
    let mut file = fs::File::create(&path)?;
    file.write_all(yaml.as_bytes())?;

    Ok(())
}

fn gen_cpp(output: &ShellcodeOutput, namespace: &str) -> String {
    let mut hpp = String::new();
    hpp.push_str("#pragma once\n");
    hpp.push_str("#include <cstdint>\n");
    hpp.push_str(&format!("namespace {}{{\n", namespace));

    hpp.push_str("\tunsigned char payload[] = {\n");
    output
        .payload
        .iter()
        .map(|v| format!("0x{:0>2X},", v))
        .collect::<Vec<_>>()
        .chunks(20)
        .for_each(|v| {
            hpp.push_str("\t\t");
            hpp.push_str(&v.join(""));
            hpp.push('\n');
        });
    hpp.push_str("\t};\n");

    hpp.push_str("\tnamespace rva{\n");
    for info in &output.rva {
        let line = if info.exported {
            format!(
                "\tconstexpr uint32_t {} = 0x{:X}; //size {:X}",
                info.name, info.offset, info.size
            )
        } else {
            format!(
                "\t//constexpr uint32_t {} = 0x{:X}; //size {:X}",
                info.name, info.offset, info.size
            )
        };
        hpp.push('\t');
        hpp.push_str(&line);
        hpp.push('\n');
    }
    hpp.push_str("\t}\n}\n");
    hpp
}

fn gen_rs(output: &ShellcodeOutput, bin_name: &str) -> String {
    let mut rs = "#![allow(dead_code)]\n".to_string();
    rs.push_str(&format!(
        "pub const PAYLOAD:&[u8] = include_bytes!(\"{}\");\n",
        bin_name
    ));
    rs.push_str("pub mod rva{\n");
    for info in &output.rva {
        let line = if info.exported {
            format!(
                "\tpub const {}:u32 = 0x{:X}; //size {:X}\n",
                info.name.to_uppercase(),
                info.offset,
                info.size
            )
        } else {
            format!(
                "\t//pub const {}:u32 = 0x{:X}; //size {:X}\n",
                info.name.to_uppercase(),
                info.offset,
                info.size
            )
        };
        rs.push_str(&line);
    }
    rs.push_str("}\n");
    rs
}
