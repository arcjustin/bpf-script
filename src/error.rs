use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{message:?} (Line {line:?})")]
    Semantics { line: u32, message: String },

    #[error("error converting integer")]
    IntegerConversion(#[from] std::num::TryFromIntError),

    #[error("syntax error")]
    Syntax(#[from] peginator::ParseError),

    #[error("failed to add btf type")]
    BtfTypeConversion(#[from] btf::Error),

    #[error("type conversion not implemented")]
    NoConversion,

    #[error("no type with that id")]
    InvalidTypeId,

    #[error("no type with that name")]
    InvalidTypeName,

    #[error("internal error occurred that shouldn't be possible")]
    InternalError,
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait SemanticsErrorContext {
    type InnerType;

    fn context(&self, line: u32, message: &str) -> Result<Self::InnerType>;
}

impl<T: Copy> SemanticsErrorContext for std::option::Option<T> {
    type InnerType = T;

    fn context(&self, line: u32, message: &str) -> Result<T> {
        self.ok_or(Error::Semantics {
            line,
            message: message.to_string(),
        })
    }
}

impl<T: Copy, E: Copy> SemanticsErrorContext for std::result::Result<T, E> {
    type InnerType = T;

    fn context(&self, line: u32, message: &str) -> Result<T> {
        self.or(Err(Error::Semantics {
            line,
            message: message.to_string(),
        }))
    }
}
