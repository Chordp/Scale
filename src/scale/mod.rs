mod error;

pub use error::{Error, Result};
use object::coff::{CoffHeader, ImageSymbol};
use object::pe::ImageFileHeader;
use object::LittleEndian as LE;
use object::{pe, read::*};
use std::collections::{HashMap};
use std::io::Write;
use log::log;

#[derive(Debug, Clone)]
pub struct Relocation {
    pub offset: u32,
    pub typ: u16,
    pub symbol: String,
}
#[derive(Debug, Clone)]
pub enum SymbolType {
    Unknown,
    Symbol(Vec<Relocation>),
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

#[derive(Debug, Default)]
pub struct Shellcode {
    exports: Vec<String>,
    symbols: HashMap<String, Symbol>,
    shell_map: HashMap<String, (usize,usize)>,
    rel64: Vec<u32>,
    pub code: Vec<u8>,
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
                let sections = header.sections(binary, offset)?;
                let symbols = header.symbols(binary)?;
                let mut exports: Vec<_> = vec![];
                if let Some((_, section)) = sections.section_by_name(symbols.strings(), b".drectve")
                {
                    if let Ok(data) = section.coff_data(binary) {
                        // EXPORT:([^,\s]+)[,\s]
                        // 正则匹配
                        let re = regex::Regex::new(r"/EXPORT:([^/\s,]+)").unwrap();
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

                let file_name = symbols.iter().find_map(|(index, symbol)| {
                    if symbol.has_aux_file_name()  {
                        let name = symbols.aux_file_name(index, symbol.number_of_aux_symbols());
                        if let Ok(name) = name {
                            return Some(String::from_utf8_lossy(name).to_string());
                        }
                    }
                    None
                }).unwrap_or(rand::random::<u16>().to_string());
                let symbols: HashMap<_, _> = symbols
                    .iter()
                    .filter_map(|(_, symbol)| {
                        let section_number = symbol.section_number();
                        let mut name = symbol.name_str(symbols.strings());
                        if section_number != 0 &&
                            (symbol.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL ||
                                name == ".data")
                        {
                            if name == ".data"{
                                name = file_name.clone() + &name;
                            }

                            let session = sections.section(section_number as usize);
                            if let Ok(session) = session {
                                let mut result = Symbol::default();
                                let mut relocats = vec![];
                                if let Ok(relocations) = session.coff_relocations(binary) {
                                    relocats = relocations
                                        .iter()
                                        .filter_map(|v| {
                                            if let Ok(symbol) = symbols
                                                .symbol(v.symbol_table_index.get(LE) as usize)
                                            {
                                                let mut name = symbol.name_str(symbols.strings());
                                                if name.starts_with("."){
                                                    let section_number = symbol.section_number();
                                                    if let Some((_,symbol)) = symbols.iter().find(|(_,symbol)|{
                                                            name != symbol.name_str(symbols.strings()) &&
                                                            section_number == symbol.section_number()
                                                    }){
                                                            name = symbol.name_str(symbols.strings());
                                                    }
                                                }
                                                if name == ".data"{
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
                                result.typ = SymbolType::Symbol(relocats);
                                result.data = match session.coff_data(binary) {
                                    Ok(data) => {
                                        if &data.len() == &0 {
                                            vec![0; session.size_of_raw_data.get(LE) as usize]
                                        } else {
                                            data.to_vec()
                                        }
                                    }
                                    _ => vec![0; session.size_of_raw_data.get(LE) as usize],
                                };
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
    fn map(&mut self, (name, symbol): (&String, &Symbol)) -> Result<()> {
        if self.shell_map.contains_key(name) {
            return Ok(());
        }
        match &symbol.typ {
            SymbolType::Unknown => Err(Error::SymbolTypeErr(name.clone()))?,
            SymbolType::Symbol(relocations)  => {
                self.shell_map.insert(name.clone(), (self.code.len(),symbol.data.len()));
                self.code.extend(&symbol.data);

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
            SymbolType::Symbol(relocations) => {
                let &(fun_offset,_size) = self
                    .shell_map
                    .get(name)
                    .ok_or(Error::MapNotFound(name.clone()))?;
                for relocation in relocations.iter() {
                    let &(symbol_offset,_size) = self
                        .shell_map
                        .get(&relocation.symbol)
                        .ok_or(Error::MapNotFound(relocation.symbol.clone()))?;

                    let offset = fun_offset + relocation.offset as usize;
                    let rel = 4 - relocation.typ as i32;
                    match relocation.typ {
                        pe::IMAGE_REL_AMD64_ADDR64=>{
                            let mut slice = &mut self.code[offset ..offset + 8];
                            let value = {
                                let value = i64::from_le_bytes(slice.try_into()?);
                                if value != -1 || value != 0 {
                                    value
                                } else {
                                    0
                                }
                            };
                            let rel = (symbol_offset as i64 + value);
                            slice.copy_from_slice(&rel.to_le_bytes()[..8]);
                            self.rel64.push(offset as u32);
                        }
                        _ => {
                            if (0..=5).contains(&rel) {
                                let mut slice = &mut self.code[offset as usize..offset as usize + 4];
                                let value = {
                                    let value = i32::from_le_bytes(slice.try_into()?);
                                    if value != -1 || value != 0 {
                                        value
                                    } else {
                                        0
                                    }
                                };

                                let rel = (symbol_offset as i32 + value) - (rel + offset as i32 + 4);
                                slice.copy_from_slice(&rel.to_le_bytes()[..4]);
                            }
                        }
                    }

                }
            }
        }

        Ok(())
    }
    pub fn parse(&mut self) -> Result<()> {
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
        for export in self.symbols.clone().iter()
            .filter(|(name,_)|kes.contains(&name)) {
            self.fix_relocation(export)?;
        }
        Ok(())
    }
    pub fn parse_head(&mut self, head: &str) -> Result<()> {
        let symbol = self
            .symbols
            .get(head)
            .ok_or(Error::SymbolNotFound(head.to_string()))?;
        self.map((&head.to_string(), &symbol.clone()))?;
        self.parse()
    }

    pub fn gen_cpp(&self, namespace: &str) -> Result<String> {
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
                hpp.push_str("\n");
            });

        hpp.push_str("\t};\n");
        if !self.rel64.is_empty(){
            hpp.push_str("\tuint32_t rel[] = {\n");
            self.rel64.iter().map(|v| format!("0x{:0>8X},", v)).for_each(|v|{
                hpp.push_str("\t\t");
                hpp.push_str(&v);
                hpp.push_str("\n");
            });
            hpp.push_str("\t};\n");
        }
        hpp.push_str("\tnamespace rva{\n");
        self.shell_map
            .iter()
            .map(|(name, (rva,size))| {
                if self.exports.contains(name) {
                    format!("\tconstexpr uint32_t {} = 0x{:X}; //size {:X}", name, rva, size)
                } else {
                    format!("\t//constexpr uint32_t {} = 0x{:X}; //size {:X}", name, rva,size)
                }
            })
            .for_each(|v| {
                hpp.push_str("\t");
                hpp.push_str(&v);
                hpp.push_str("\n");
            });
        hpp.push_str("\t}\n}\n");
        Ok(hpp)
    }
}
