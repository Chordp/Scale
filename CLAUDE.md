# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Scale 是一个 Rust 命令行工具，用于从编译后的二进制目标文件（COFF、PE、Archive）中提取 shellcode，并生成多种格式的输出（C++、Rust、二进制）。

## 构建命令

```bash
cargo build              # Debug 构建
cargo build --release    # Release 构建
cargo fmt                # 代码格式化
cargo clippy             # 代码检查
```

## 运行示例

```bash
scale --input <input.obj> --output <output>
scale --input file.obj --mega --align --namespace my_shellcode --head ExportedFunc
```

CLI 参数：
- `--input <INPUT>` - 输入目标文件（必需）
- `--output <OUTPUT>` - 输出文件路径
- `--namespace <NAMESPACE>` - C++ 命名空间（默认: shellcode）
- `--head <HEAD>` - 指定放在 shellcode 头部的函数
- `--mega` - 启用 data/code 分离模式
- `--align` - 启用 8 字节对齐

## 架构

```
src/
├── lib.rs    # 核心库
├── error.rs  # 错误类型
└── main.rs   # CLI
```

### 核心库 (lib.rs)

- `Config` - 配置（head, mega, align）
- `Shellcode` - 主处理器，`make()` 返回 `ShellcodeOutput`
- `ShellcodeOutput` - 结果（payload, rva）
- `RvaInfo` - RVA 信息（name, offset, size, exported）

**可选 Features:**
```toml
scale = { version = "0.1", features = ["serde"] }
```
- `serde` - 为 `ShellcodeOutput` 和 `RvaInfo` 启用 Serialize/Deserialize

```rust
use scale::{Config, Shellcode};

let config = Config::new()
    .with_mega(true)
    .with_head("entry_func");

let mut shellcode = Shellcode::new(config);
let output = shellcode.make(&binary_data)?;
// output.payload - shellcode 字节
// output.rva - Vec<RvaInfo>
```

### CLI (main.rs)

- `Args` - clap 参数定义
- `enable_ansi_support()` - Windows ANSI 支持
- `gen_cpp()` / `gen_rs()` - 代码生成
- `write_output()` - 输出 .bin/.hpp/.rs 文件

## 输出格式

- `.bin` - 原始 shellcode
- `.hpp` - C++ 头文件
- `.rs` - Rust 模块
- `.json` - JSON 格式
- `.yaml` - YAML 格式
