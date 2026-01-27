# Scale

从 COFF/PE/Archive 二进制文件提取 shellcode 的 Rust 工具。

## 功能

- 解析 COFF 目标文件、PE 文件、静态库 (.lib/.a)
- 自动修复重定位（支持 AMD64 和 i386）
- 多种输出格式：`.bin`、`.hpp`、`.rs`、`.json`、`.yaml`
- 可作为库集成到其他项目

## 安装

```bash
cargo install --path .
```

## 命令行使用

```bash
# 基本用法
scale --input shellcode.obj --output output

# 完整参数
scale --input shellcode.lib \
      --output output \
      --head entry \           # 指定入口函数放在头部
      --mega \                 # data/code 分离模式
      --align \                # 8 字节对齐
      --namespace my_shellcode # C++ 命名空间
```

### 参数说明

| 参数 | 短参数 | 说明 | 默认值 |
|------|--------|------|--------|
| `--input` | `-i` | 输入文件路径 | 必需 |
| `--output` | `-o` | 输出文件路径 | 同输入文件 |
| `--head` | | 指定放在 shellcode 头部的函数 | |
| `--mega` | `-m` | 启用 data/code 分离模式 | false |
| `--align` | `-a` | 启用 8 字节对齐 | false |
| `--namespace` | `-n` | C++ 命名空间名称 | shellcode |

## 库使用

```toml
[dependencies]
scale = { path = "path/to/scale" }
# 或禁用 serde
# scale = { path = "path/to/scale", default-features = false }
```

```rust
use scale::{Config, Shellcode};

let binary = std::fs::read("shellcode.lib")?;

let config = Config::new()
    .with_head("entry")
    .with_mega(true)
    .with_align(true);

let mut shellcode = Shellcode::new(config);
let output = shellcode.make(&binary)?;

// output.payload - shellcode 字节数据
// output.rva - Vec<RvaInfo> 符号信息
for rva in &output.rva {
    println!("{}: offset=0x{:X}, size=0x{:X}, exported={}",
        rva.name, rva.offset, rva.size, rva.exported);
}
```

## 输出格式

| 扩展名 | 说明 |
|--------|------|
| `.bin` | 原始 shellcode 二进制 |
| `.hpp` | C++ 头文件（payload 数组 + RVA 常量） |
| `.rs` | Rust 模块（include_bytes! + RVA 常量） |
| `.json` | JSON 格式 |
| `.yaml` | YAML 格式 |

## 示例

在 VS 开发者命令行中运行：

```bash
cargo run --example demo
```

示例会：
1. 读取 `templates/VsTemp/x64/Release/VsTemp.lib`
2. 使用 scale 生成 shellcode
3. 分配可执行内存并执行

## Features

| Feature | 说明 | 默认 |
|---------|------|------|
| `serde` | 为 `ShellcodeOutput` 和 `RvaInfo` 启用序列化 | ✓ |

## License

MIT
