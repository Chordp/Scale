#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CoffError(#[from] object::read::Error),
    #[error("符号表未找到: {0}")]
    SymbolNotFound(String),
    #[error("符号表类型错误: {0}")]
    SymbolTypeErr(String),
    #[error("映射表未找到: {0}")]
    MapNotFound(String),
    #[error("Io错误: {0}")]
    IoError(#[from] std::io::Error),
    #[error("切片转换错误: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("输出目标并非文件")]
    NotFile,
}

pub type Result<T> = std::result::Result<T, Error>;
