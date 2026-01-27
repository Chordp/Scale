mod error;

pub use error::{Error, Result};
use lazy_regex::regex;
use object::coff::{CoffHeader, ImageSymbol};
use object::pe::{
    ImageFileHeader, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA,
};
use object::LittleEndian as LE;
use object::{pe, read::*};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// Shellcode 生成配置
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 指定某函数在 shellcode 头部
    pub head: Option<String>,
    /// 完全体 shellcode，data 和 code 分离
    pub mega: bool,
    /// 是否对 shellcode 进行 8 字节对齐
    pub align: bool,
}

impl Config {
    pub fn new() -> Self {
        Self {
            head: None,
            mega: false,
            align: false,
        }
    }

    pub fn with_head(mut self, head: impl Into<String>) -> Self {
        self.head = Some(head.into());
        self
    }

    pub fn with_mega(mut self, mega: bool) -> Self {
        self.mega = mega;
        self
    }

    pub fn with_align(mut self, align: bool) -> Self {
        self.align = align;
        self
    }
}

/// RVA 信息
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RvaInfo {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub exported: bool,
}

/// Shellcode 生成结果
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShellcodeOutput {
    /// 生成的 shellcode 数据
    pub payload: Vec<u8>,
    /// RVA 信息列表
    pub rva: Vec<RvaInfo>,
}

#[derive(Debug, Clone)]
struct Relocation {
    offset: u32,
    typ: u16,
    symbol: String,
}

#[derive(Debug, Clone)]
enum SymbolType {
    Unknown,
    Text(Vec<Relocation>),
    Data(Vec<Relocation>),
}

#[derive(Debug, Clone)]
struct Symbol {
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
    symbols: HashMap<String, Rc<Symbol>>,
    shell_map: HashMap<String, (usize, usize)>,
    rel64: Vec<u32>,
    code: Vec<u8>,
    layout: (usize, usize),
    size: Option<(usize, usize)>,
    machine: Option<u16>,
    config: Config,
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
    pub fn new(config: Config) -> Self {
        Self {
            exports: vec![],
            symbols: HashMap::new(),
            shell_map: HashMap::new(),
            rel64: vec![],
            code: vec![],
            layout: (0, 0),
            machine: None,
            config,
            size: None,
        }
    }
    /// 处理二进制数据，生成 shellcode
    pub fn make(&mut self, binary: &[u8]) -> Result<ShellcodeOutput> {
        self.form_binary(binary)?;
        self.parse()?;

        let rva = self
            .shell_map
            .iter()
            .map(|(name, (offset, size))| RvaInfo {
                name: name.clone(),
                offset: *offset,
                size: *size,
                exported: self.exports.contains(name),
            })
            .collect();

        Ok(ShellcodeOutput {
            payload: self.code.clone(),
            rva,
        })
    }
    fn form_binary(&mut self, binary: &[u8]) -> Result<()> {
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
                if let Some((_, section)) = sections.section_by_name(symbols.strings(), b".drectve")
                {
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
                        let class = symbol.storage_class();
                        if section_number != 0
                            && (class == pe::IMAGE_SYM_CLASS_EXTERNAL
                            || class == pe::IMAGE_SYM_CLASS_STATIC
                            || name == ".data")
                        {
                            if name == ".data" {
                                name = file_name.clone() + &name;
                            }

                            let session = sections.section(SectionIndex(section_number as usize));

                            match session {
                                Ok(session) => {
                                    let mut result = Symbol::default();

                                    let flag = session.characteristics.get(LE);
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
                                                    let mut name =
                                                        symbol.name_str(symbols.strings());
                                                    if name.starts_with(".") {
                                                        let section_number =
                                                            symbol.section_number();
                                                        if let Some((_, symbol)) =
                                                            symbols.iter().find(|(_, symbol)| {
                                                                name != symbol
                                                                    .name_str(symbols.strings())
                                                                    && section_number
                                                                    == symbol.section_number()
                                                            })
                                                        {
                                                            name =
                                                                symbol.name_str(symbols.strings());
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
                                    if flag & IMAGE_SCN_CNT_CODE != 0 {
                                        result.typ = SymbolType::Text(relocats);
                                    } else if (flag & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0
                                        || (flag & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0
                                    {
                                        result.typ = SymbolType::Data(relocats);
                                    }

                                    return Some((name, Rc::new(result)));
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "解析符号表错误: {} {} {}",
                                        e,
                                        symbol.name_str(symbols.strings()),
                                        section_number
                                    );
                                }
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

    fn map(&mut self, name: &str, symbol: &Symbol) -> Result<()> {
        if self.shell_map.contains_key(name) {
            return Ok(());
        }
        match &symbol.typ {
            SymbolType::Unknown => Err(Error::SymbolType(name.to_owned()))?,
            SymbolType::Text(relocations) | SymbolType::Data(relocations) => {
                //是否为mini
                match self.size {
                    Some((code_len, _)) => match &symbol.typ {
                        SymbolType::Text(_) => {
                            let code =
                                &mut self.code[self.layout.0..self.layout.0 + symbol.data.len()];
                            code.copy_from_slice(&symbol.data);
                            self.shell_map
                                .insert(name.to_owned(), (self.layout.0, symbol.data.len()));
                            self.layout.0 += symbol.data.len();
                            // 8 字节对齐
                            if self.config.align {
                                let align = 8 - (self.layout.0 % 8);
                                if align != 8 {
                                    self.layout.0 += align;
                                }
                            }
                        }
                        SymbolType::Data(_) => {
                            let code = &mut self.code[code_len + self.layout.1
                                ..code_len + self.layout.1 + symbol.data.len()];
                            code.copy_from_slice(&symbol.data);
                            self.shell_map.insert(
                                name.to_owned(),
                                (code_len + self.layout.1, symbol.data.len()),
                            );
                            self.layout.1 += symbol.data.len();
                            if self.config.align {
                                let align = 8 - (self.layout.1 % 8);
                                if align != 8 {
                                    self.layout.1 += align;
                                }
                            }
                        }
                        _ => (),
                    },
                    None => {
                        self.shell_map
                            .insert(name.to_owned(), (self.code.len(), symbol.data.len()));
                        self.code.extend(&symbol.data);
                        // 8 字节对齐
                        if self.config.align {
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
                        Some(symbol) => self.map(&relocation.symbol, &symbol.clone())?,
                    }
                }
            }
        }
        Ok(())
    }

    fn fix_relocation(&mut self, name: &str, symbol: &Symbol) -> Result<()> {
        match &symbol.typ {
            SymbolType::Unknown => Err(Error::SymbolType(name.to_owned()))?,
            SymbolType::Text(relocations) | SymbolType::Data(relocations) => {
                let &(fun_offset, _size) = self
                    .shell_map
                    .get(name)
                    .ok_or(Error::MapNotFound(name.to_owned()))?;
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

    fn get_layout(&self, seeds: &HashMap<String, Rc<Symbol>>) -> (usize, usize) {
        let mut code_len = 0;
        let mut data_len = 0;
        let mut symbols = HashMap::new();
        let mut visited: HashSet<String> = HashSet::new();

        // 初始化待处理栈：从 seeds 的 key 开始
        let mut stack: Vec<String> = seeds.keys().cloned().collect();

        while let Some(name) = stack.pop() {
            if !visited.insert(name.clone()) {
                continue; // 已处理过
            }
            if let Some(sym) = self.symbols.get(&name) {
                symbols.insert(name.clone(), sym.clone());
                // 仅 Text/Data 类型会产生依赖
                for relocation in match &sym.typ {
                    SymbolType::Text(rels) | SymbolType::Data(rels) => rels,
                    _ => continue,
                } {
                    let dep = &relocation.symbol;
                    if !visited.contains(dep) {
                        stack.push(dep.clone());
                    }
                }
            }
        }

        for symbol in symbols.values() {
            match &symbol.typ {
                SymbolType::Text(_) => {
                    code_len += symbol.data.len();
                    if self.config.align {
                        let align = 8 - (code_len % 8);
                        if align != 8 {
                            code_len += align;
                        }
                    }
                }
                SymbolType::Data(_) => {
                    data_len += symbol.data.len();
                    if self.config.align {
                        let align = 8 - (data_len % 8);
                        if align != 8 {
                            data_len += align;
                        }
                    }
                }
                _ => (),
            }
        }
        let code_len = (code_len + 0x1000 - 1) & !0xFFF;
        let data_len = (data_len + 0x1000 - 1) & !0xFFF;
        (code_len, data_len)
    }

    fn parse(&mut self) -> Result<()> {
        let exports = self
            .symbols
            .clone()
            .into_iter()
            .filter(|(name, _)| self.exports.contains(name))
            .collect::<HashMap<_, _>>();

        println!("{:#?}", self
            .symbols);
        // 完全体
        if self.config.mega {
            let (code_len, data_len) = self.get_layout(&exports);
            self.size = Some((code_len, data_len));
            self.code = vec![0; code_len + data_len];
        }

        if let Some(head) = &self.config.head {
            let symbol = self
                .symbols
                .get(head)
                .ok_or(Error::SymbolNotFound(head.to_string()))?;
            self.map(&head.to_string(), &symbol.clone())?;
        }

        for (name, symbol) in exports.iter() {
            self.map(name, symbol)?;
        }
        let kes = self.shell_map.keys().cloned().collect::<Vec<_>>();
        for (name, symbol) in self
            .symbols
            .clone()
            .iter()
            .filter(|(name, _)| kes.contains(name))
        {
            self.fix_relocation(name, symbol)?;
        }
        Ok(())
    }
}
