//! 示例：调用 MSBuild 编译 VsTemp 项目，生成 shellcode 并执行
//!
//! 运行方式：
//! 1. 打开 "x64 Native Tools Command Prompt for VS"
//! 2. cargo run --example demo

use color_eyre::eyre::eyre;
use scale::{Config, Shellcode};
use std::process::Command;
use std::{env, fs, mem, ptr};

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let lib_file = format!("{}/templates/VsTemp/x64/Release/VsTemp.lib", manifest_dir);

    // 2. 使用 scale 生成 shellcode
    println!("[*] 生成 shellcode ...");
    let binary = fs::read(&lib_file)?;
    let config = Config::new().with_head("go");
    let mut sc = Shellcode::new(config);
    let output = sc.make(&binary)?;

    println!("[+] Shellcode 大小: {} bytes", output.payload.len());
    println!("[+] RVA 信息:");
    for rva in &output.rva {
        let export_mark = if rva.exported { "[E]" } else { "   " };
        println!(
            "    {} {} @ 0x{:X} (size: 0x{:X})",
            export_mark, rva.name, rva.offset, rva.size
        );
    }

    // 3. 执行 shellcode
    #[cfg(target_os = "windows")]
    unsafe {
        use windows::Win32::System::Memory::*;

        println!("[*] 分配可执行内存 ...");
        let mem = VirtualAlloc(
            None,
            output.payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if mem.is_null() {
            return Err(eyre!("VirtualAlloc 失败"));
        }

        // 复制 shellcode
        ptr::copy_nonoverlapping(
            output.payload.as_ptr(),
            mem as *mut u8,
            output.payload.len(),
        );

        // 找到 entry 函数的 RVA
        let entry_rva = output
            .rva
            .iter()
            .find(|r| r.name == "go")
            .map(|r| r.offset)
            .unwrap_or(0);

        let entry_ptr = (mem as usize + entry_rva) as *const ();
        let entry_fn: extern "C" fn() = mem::transmute(entry_ptr);

        println!("[*] 执行 shellcode (entry @ 0x{:X}) ...", entry_rva);
        entry_fn();

        // 释放内存
        VirtualFree(mem, 0, MEM_RELEASE)?;
    }

    #[cfg(not(target_os = "windows"))]
    println!("[!] 非 Windows 平台，跳过执行");

    Ok(())
}
