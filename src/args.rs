use std::fs;
use std::io::Write;
use std::path::Path;
use clap::Parser;
use crate::scale;
use crate::scale::Shellcode;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub head: Option<String>,
    #[arg(short, long)]
    pub input: String,
    #[arg(short, long, default_value = "shellcode.h")]
    pub output: String,
    #[arg(short, long, default_value = "shellcode")]
    pub namespace: String,
    #[arg(short, long, default_value = "false")]
    pub bin: bool,
    #[arg(short, long, default_value = "false")]
    pub align:bool,
}
// impl Args{
//     pub fn shellcode_gen(&self) -> scale::Result<()> {
//         let file = fs::read(&self.input)?;
//         let mut shell = Shellcode::default();
//         shell.form_binary(&file)?;
//         match &self.head {
//             None => shell.parse()?,
//             Some(head) => shell.parse_head(head.as_str())?,
//         }
//         let shellcode = shell.gen_cpp(&self.namespace)?;
//         let mut file = fs::File::create(&self.output)?;
//
//         file.write_all(shellcode.as_bytes())?;
//
//         if self.bin {
//             // 修改output 后缀为 bin
//             let mut output = Path::new(&self.output).to_path_buf();
//             output.set_extension("bin");
//             let mut file = fs::File::create(output)?;
//             file.write_all(&shell.code)?;
//         }
//         Ok(())
//     }
// }