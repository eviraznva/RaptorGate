use crate::rule_tree::{matcher::Match, parsing::{ast::Parser, lexer::Lexer}};

mod ast;
mod lexer;
mod lower;

pub fn parse_rule_tree(input: &str) -> Result<Match, anyhow::Error> {
    let mut lexer = Lexer::new();
    let tokens = lexer.tokenize(input)?;
    let mut parser = Parser::new(tokens);
    let ast = parser.parse()?;
    Ok(lower::lower(ast)?)
}