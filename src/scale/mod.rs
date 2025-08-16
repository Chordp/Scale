mod error;
use crate::args::Args;
pub use error::{Error, Result};
use object::coff::{CoffHeader, ImageSymbol};
use object::pe::{ImageFileHeader, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA};
use object::LittleEndian as LE;
use object::{pe, read::*};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use lazy_regex::regex;

#[derive(Debug, Clone)]
pub struct Relocation {
    pub offset: u32,
    pub typ: u16,
    pub symbol: String,
}
#[derive(Debug, Clone)]
pub enum SymbolType {
    Unknown,
    Text(Vec<Relocation>),
    Data(Vec<Relocation>),
}

#[derive(Debug, Clone)]
pub struct Symbol {
    data: Vec<u8>,
    typ: SymbolType,
}

impl Default for Symbol {
    fn default() -> Self {
        Self {
            data: vec![],
            typ: SymbolType::Unknown,
        }
    }
}

#[derive(Debug)]
pub struct Shellcode {
    exports: Vec<String>,
    symbols: HashMap<String, Symbol>,
    shell_map: HashMap<String, (usize, usize)>,
    rel64: Vec<u32>,
    code: Vec<u8>,
    layout: (usize, usize),
    size: Option<(usize, usize)>,
    machine: Option<u16>,
    args: Args,
}

trait SymbolExt {
    fn name_str<'data, R: ReadRef<'data>>(&'data self, strings: StringTable<'data, R>) -> String;
}
impl SymbolExt for pe::ImageSymbol {
    fn name_str<'data, R: ReadRef<'data>>(&'data self, strings: StringTable<'data, R>) -> String {
        match self.name(strings) {
            Ok(name) => String::from_utf8_lossy(name),
            Err(_) => String::from_utf8_lossy(&self.name),
        }
        .to_string()
    }
}
impl Shellcode {
    pub fn form_binary(&mut self, binary: &[u8]) -> Result<()> {
        match FileKind::parse(binary)? {
            FileKind::Archive => {
                let archive = archive::ArchiveFile::parse(binary)?;
                for member in archive.members().flatten() {
                    let data = member.data(binary)?;
                    self.form_binary(data)?;
                }
            }
            FileKind::Coff => {
                let mut offset = 0;
                let header = ImageFileHeader::parse(binary, &mut offset)?;
                if self.machine.is_none() {
                    self.machine = Some(header.machine());
                }
                let sections = header.sections(binary, offset)?;
                let symbols = header.symbols(binary)?;
                let mut exports: Vec<_> = vec![];
                //取导出
                if let Some((_, section)) = sections.section_by_name(symbols.strings(), b".drectve") {
                    if let Ok(data) = section.coff_data(binary) {
                        // EXPORT:([^,\s]+)[,\s]
                        // 正则匹配
                        let re = regex!(r"/EXPORT:([^/\s,]+)");
                        exports = re
                            .captures_iter(&String::from_utf8_lossy(data))
                            .filter_map(|cap| cap.get(1))
                            .map(|cap| cap.as_str().to_string())
                            .collect();
                    }
                }
                let exports = symbols
                    .iter()
                    .filter_map(|(_, symbol)| {
                        let name = symbol.name_str(symbols.strings());

                        if exports.contains(&name)
                            && symbol.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
                        {
                            return Some(name);
                        }
                        None
                    })
                    .collect::<Vec<_>>();
                self.exports.extend(exports);

                let file_name = symbols
                    .iter()
                    .find_map(|(index, symbol)| {
                        if symbol.has_aux_file_name() {
                            let name = symbols.aux_file_name(index, symbol.number_of_aux_symbols());
                            if let Ok(name) = name {
                                return Some(String::from_utf8_lossy(name).to_string());
                            }
                        }
                        None
                    })
                    .unwrap_or(rand::random::<u16>().to_string());

                let symbols: HashMap<_, _> = symbols
                    .iter()
                    .filter_map(|(_, symbol)| {
                        let section_number = symbol.section_number();
                        let mut name = symbol.name_str(symbols.strings());
                        if section_number != 0
                            && (symbol.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
                                || name == ".data")
                        {
                            if name == ".data" {
                                name = file_name.clone() + &name;
                            }
                            let session = sections.section(SectionIndex(section_number as usize));
                            if let Ok(session) = session {
                                let mut result = Symbol::default();

                                let flag =  session.characteristics.get(LE);
                                result.data = match session.coff_data(binary) {
                                    Ok(data) => {
                                        if data.is_empty() {
                                            vec![0; session.size_of_raw_data.get(LE) as usize]
                                        } else {
                                            data.to_vec()
                                        }
                                    }
                                    _ => vec![0; session.size_of_raw_data.get(LE) as usize],
                                };
                                let mut relocats = vec![];
                                if let Ok(relocations) = session.coff_relocations(binary) {
                                    relocats = relocations
                                        .iter()
                                        .filter_map(|v| {
                                            if let Ok(symbol) = symbols.symbol(SymbolIndex(
                                                v.symbol_table_index.get(LE) as usize,
                                            )) {
                                                let mut name = symbol.name_str(symbols.strings());
                                                if name.starts_with(".") {
                                                    let section_number = symbol.section_number();
                                                    if let Some((_, symbol)) =
                                                        symbols.iter().find(|(_, symbol)| {
                                                            name != symbol
                                                                .name_str(symbols.strings())
                                                                && section_number
                                                                == symbol.section_number()
                                                        })
                                                    {
                                                        name = symbol.name_str(symbols.strings());
                                                    }
                                                }
                                                if name == ".data" {
                                                    name = file_name.clone() + &name;
                                                }
                                                let relocation = Relocation {
                                                    offset: v.virtual_address.get(LE),
                                                    typ: v.typ.get(LE),
                                                    symbol: name,
                                                };
                                                return Some(relocation);
                                            }
                                            None
                                        })
                                        .collect::<Vec<_>>()
                                }
                                if flag & IMAGE_SCN_CNT_CODE != 0{
                                    result.typ = SymbolType::Text(relocats);

                                }else if (flag & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 ||
                                    (flag & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0{
                                    result.typ = SymbolType::Data(relocats);
                                }

                                return Some((name, result));
                            }
                        }
                        None
                    })
                    .collect();

                self.symbols.extend(symbols);
            }
            _ => (),
        }

        Ok(())
    }
    pub fn new(args: Args) -> Self {
        Self {
            exports: vec![],
            symbols: HashMap::new(),
            shell_map: HashMap::new(),
            rel64: vec![],
            code: vec![],
            layout: (0, 0),
            machine: None,
            args,
            size: None,
        }
    }
    fn map(&mut self, (name, symbol): (&String, &Symbol)) -> Result<()> {
        if self.shell_map.contains_key(name) {
            return Ok(());
        }
        match &symbol.typ {
            SymbolType::Unknown => Err(Error::SymbolTypeErr(name.clone()))?,
            SymbolType::Text(relocations) | SymbolType::Data(relocations) => {
                //是否为mini
                match self.size{
                    Some((code_len,_)) => match &symbol.typ{
                        SymbolType::Text(_) => {
                            let code = &mut self.code[self.layout.0..self.layout.0 + symbol.data.len()];
                            code.copy_from_slice(&symbol.data);
                            self.shell_map
                                .insert(name.clone(), (self.layout.0, symbol.data.len()));
                            self.layout.0 += symbol.data.len();
                            // 8 字节对齐
                            if self.args.align {
                                let align = 8 - (self.layout.0 % 8);
                                if align != 8 {
                                    self.layout.0 += align;
                                }
                            }
                        }
                        SymbolType::Data(_) => {
                            let code = &mut self.code[code_len + self.layout.1 .. code_len + self.layout.1  + symbol.data.len()];
                            code.copy_from_slice(&symbol.data);
                            self.shell_map
                                .insert(name.clone(), (code_len + self.layout.1, symbol.data.len()));
                            self.layout.1 += symbol.data.len();
                            if self.args.align {
                                let align = 8 - (self.layout.1 % 8);
                                if align != 8 {
                                    self.layout.1 += align;
                                }
                            }
                        }
                        _=>()
                    }
                    None => {
                        self.shell_map
                            .insert(name.clone(), (self.code.len(), symbol.data.len()));
                        self.code.extend(&symbol.data);
                        // 8 字节对齐
                        if self.args.align {
                            let align = 8 - (self.code.len() % 8);
                            if align != 8 {
                                self.code.extend(vec![0; align]);
                            }
                        }
                    }
                }

                //修复引用
                for relocation in relocations.iter() {
                    match self.symbols.get(&relocation.symbol) {
                        None => Err(Error::SymbolNotFound(relocation.symbol.clone()))?,
                        Some(symbol) => self.map((&relocation.symbol, &symbol.clone()))?,
                    }
                }
            }
        }
        Ok(())
    }
    fn fix_relocation(&mut self, (name, symbol): (&String, &Symbol)) -> Result<()> {
        match &symbol.typ {
            SymbolType::Unknown => Err(Error::SymbolTypeErr(name.clone()))?,
            SymbolType::Text(relocations) | SymbolType::Data(relocations) => {
                let &(fun_offset, _size) = self
                    .shell_map
                    .get(name)
                    .ok_or(Error::MapNotFound(name.clone()))?;
                for relocation in relocations.iter() {
                    let &(symbol_offset, _size) = self
                        .shell_map
                        .get(&relocation.symbol)
                        .ok_or(Error::MapNotFound(relocation.symbol.clone()))?;

                    let offset = fun_offset + relocation.offset as usize;
                    match self.machine {
                        Some(pe::IMAGE_FILE_MACHINE_AMD64) => {
                            let rel = relocation.typ - 4;
                            match relocation.typ {
                                pe::IMAGE_REL_AMD64_ADDR64 => {
                                    let slice = &mut self.code[offset..offset + 8];
                                    let value = {
                                        let value = i64::from_le_bytes(slice.try_into()?);
                                        if value != -1 || value != 0 {
                                            value
                                        } else {
                                            0
                                        }
                                    };
                                    let rel = symbol_offset as i64 + value;
                                    slice.copy_from_slice(&rel.to_le_bytes()[..8]);
                                    self.rel64.push(offset as u32);
                                }
                                _ => {
                                    if (0..=5).contains(&rel) {
                                        let slice = &mut self.code[offset..offset + 4];
                                        let value = {
                                            let value = i32::from_le_bytes(slice.try_into()?);
                                            if value != -1 || value != 0 {
                                                value
                                            } else {
                                                0
                                            }
                                        };
                                        let rel = (symbol_offset as i32 + value)
                                            - (rel as usize + offset + 4) as i32;
                                        slice.copy_from_slice(&rel.to_le_bytes()[..4]);
                                    }
                                }
                            }
                        }
                        Some(pe::IMAGE_FILE_MACHINE_I386) => match relocation.typ {
                            pe::IMAGE_REL_I386_REL32 => {
                                let slice = &mut self.code[offset..offset + 4];
                                let value = {
                                    let value = i32::from_le_bytes(slice.try_into()?);
                                    if value != -1 || value != 0 {
                                        value
                                    } else {
                                        0
                                    }
                                };
                                let rel = (symbol_offset as i32 + value) - (offset + 4) as i32;
                                slice.copy_from_slice(&rel.to_le_bytes()[..4]);
                            }
                            pe::IMAGE_REL_I386_DIR32 => {
                                tracing::info!(
                                    "{} {} {} {}",
                                    name,
                                    offset,
                                    symbol_offset,
                                    relocation.typ
                                );
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
    pub fn parse(&mut self) -> Result<()> {

        // 完全体
        if self.args.mega{
            let code_len:usize = self
                .symbols.iter().filter_map(|(_,n)|{
                if let SymbolType::Text(_) = n.typ  {
                    let mut res = n.data.len();
                    if self.args.align {
                        // 8 字节对齐
                        let align = 8 - (n.data.len() % 8);
                        if align != 8 {
                            res += align
                        }
                    }
                    Some(res)
                }else {
                    None
                }
            }).sum();
            let code_len = (code_len + 0x1000 - 1) & !0xFFF;
            let data_len:usize = self
                .symbols.iter().filter_map(|(_,n)|{
                if let SymbolType::Data(_) = n.typ  {
                    let mut res = n.data.len();
                    if self.args.align {
                        // 8 字节对齐
                        let align = 8 - (n.data.len() % 8);
                        if align != 8 {
                            res += align
                        }
                    }
                    Some(res)
                }else {
                    None
                }
            }).sum();
            self.size = Some((code_len, data_len));
            self.code = vec![0; code_len + data_len];
        }

        if let Some(head) = &self.args.head {
            let symbol = self
                .symbols
                .get(head)
                .ok_or(Error::SymbolNotFound(head.to_string()))?;
            self.map((&head.to_string(), &symbol.clone()))?;
        }

        let exports = self
            .symbols
            .clone()
            .into_iter()
            .filter(|(name, _)| self.exports.contains(name))
            .collect::<HashMap<_, _>>();
        for export in exports.iter() {
            self.map(export)?;
        }
        let kes = self.shell_map.keys().cloned().collect::<Vec<_>>();
        for export in self
            .symbols
            .clone()
            .iter()
            .filter(|(name, _)| kes.contains(name))
        {
            self.fix_relocation(export)?;
        }
        Ok(())
    }
    pub fn gen_cpp(&self, namespace: &str) -> String {
        let mut hpp = String::new();
        hpp.push_str("#pragma once\n");
        hpp.push_str("#include <cstdint>\n");
        hpp.push_str(&format!("namespace {}{{\n", namespace));

        hpp.push_str("\tunsigned char payload[] = {\n");
        self.code
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
        if let Some((code_len, data_len)) = self.size {
            hpp.push_str(&format!("\tconstexpr size_t code_size = 0x{:08X};\n", code_len));
            hpp.push_str(&format!("\tconstexpr size_t data_size = 0x{:08X};\n", data_len));
        }
        if !self.rel64.is_empty() {
            hpp.push_str("\tuint32_t rel[] = {\n");
            self.rel64
                .iter()
                .map(|v| format!("0x{:0>8X},", v))
                .for_each(|v| {
                    hpp.push_str("\t\t");
                    hpp.push_str(&v);
                    hpp.push('\n');
                });
            hpp.push_str("\t};\n");
        }
        hpp.push_str("\tnamespace rva{\n");
        self.shell_map
            .iter()
            .map(|(name, (rva, size))| {
                if self.exports.contains(name) {
                    format!(
                        "\tconstexpr uint32_t {} = 0x{:X}; //size {:X}",
                        name, rva, size
                    )
                } else {
                    format!(
                        "\t//constexpr uint32_t {} = 0x{:X}; //size {:X}",
                        name, rva, size
                    )
                }
            })
            .for_each(|v| {
                hpp.push('\t');
                hpp.push_str(&v);
                hpp.push('\n');
            });
        hpp.push_str("\t}\n}\n");
        hpp
    }
    pub fn gen_rs(&self,out:String) -> String {
        let mut rs = String::new();
        if let Some((code_len, data_len)) = self.size {
            rs.push_str(&format!("const CODE_SIZE:usize = 0x{:08X};\n", code_len));
            rs.push_str(&format!("const DATA_SIZE:usize = 0x{:08X};\n", data_len));
        }
        rs.push_str(&format!("const PAYLOAD:&[u8] = include_bytes!(\"{out}\");\n"));
        if !self.rel64.is_empty() {
            rs.push_str(&format!("const rel[u32;{}] = [\n", self.rel64.len()));
            self.rel64.iter().for_each(|v| {
                rs.push_str(&format!("\t0x{:0>8X},\n", v));
            });
            rs.push_str("];\n");
        }
        rs.push_str("mod rva{\n");
        self.shell_map.iter().for_each(|(name, (rva, size))| {
            let s = if self.exports.contains(name) {
                format!("\tconst {}:u32 = 0x{:X}; //size {:X}\n", name.to_uppercase(), rva, size)
            } else {
                format!("\t//const {}:u32 = 0x{:X}; //size {:X}\n", name.to_uppercase(), rva, size)
            };
            rs.push_str(&s);
        });
        rs.push_str("}\n");

        rs
    }
    pub fn gen(&mut self) -> Result<()> {
        let file = fs::read(&self.args.input)?;
        self.form_binary(&file)?;
        self.parse()?;

        let mut output =
            Path::new(self.args.output.as_ref().unwrap_or(&self.args.input)).to_path_buf();
        {
            output.set_extension("bin");
            let mut file = fs::File::create(&output)?;
            file.write_all(&self.code)?;
        }
        let cpp = self.gen_cpp(&self.args.namespace);
        let rs = self.gen_rs(output.file_name().ok_or(Error::NotFile)?.display().to_string());
        {
            output.set_extension("cpp");
            let mut file = fs::File::create(&output)?;
            file.write_all(cpp.as_bytes())?;
        }
        {
            output.set_extension("rs");
            let mut file = fs::File::create(&output)?;
            file.write_all(rs.as_bytes())?;
        }

        Ok(())
    }
}
