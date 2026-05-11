use derive_more::{Debug, Display};
use thiserror::Error;

use crate::rule_tree::{
    matcher::Match,
    parsing::{ast::{ParseError, Parser}, lexer::{Lexer, LexerError}, lower::LowerError},
};

mod ast;
mod lexer;
mod lower;

pub fn parse_rule_tree(input: &str) -> Result<Match, RaptorlangError> {
    let mut lexer = Lexer::new();
    let tokens = lexer.tokenize(input)?;
    let mut parser = Parser::new(tokens);
    let ast = parser.parse()?;
    Ok(lower::lower(ast)?)
}

#[derive(Error, Debug, Display)]
pub enum RaptorlangError {
    LexerError(#[from] LexerError),
    ParserError(#[from] ParseError),
    LoweringError(#[from] LowerError),
}
