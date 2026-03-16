use std::panic;

use derive_more::Display;
use thiserror::Error;

use crate::rule_tree::parsing::lexer::{KeywordType, PatternType, Token, TokenType};

struct AstMatch {
    kind: String,
    arms: Vec<AstArm>,
}

struct AstArm {
    pattern: AstPattern,
    body: AstBody,
}

enum AstPattern {
    Equal(AstValue),
    Greater(AstValue),
    LesserOrEqual(AstValue),
    Range(AstValue, AstValue),
    Or(Vec<AstPattern>),
    Glob,
}

enum AstValue {
    Number(u64),
    Str(String),
    Ident(String),
}

enum AstBody {
    Verdict(String),
    Match(AstMatch),
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Result<Token, ParseError> {
        self.tokens.get(self.pos).ok_or(ParseError::UnexpectedEndOfInput).cloned()
    }

    fn consume(&mut self) -> Result<Token, ParseError> {
        let t = self.tokens.get(self.pos).ok_or(ParseError::UnexpectedEndOfInput).cloned()?;
        self.pos += 1;
        Ok(t)
    }

    fn expect_keyword(&mut self, keyword: KeywordType) -> Result<(), ParseError> {
        let token = self.consume()?;

        match token.kind {
            TokenType::Keyword(k) if k == keyword => Ok(()),
            _ => Err(ParseError::UnexpectedToken(token)),
        }
    }

    fn parse_ident(&mut self) -> Result<String, ParseError> {
        let token = self.consume()?;

        match token.kind {
            TokenType::Identifier(id) => Ok(id),
            _ => Err(ParseError::UnexpectedToken(token)),
        }
    }

    fn expect_token(&mut self, expected: TokenType) -> Result<(), ParseError> {
        let token = self.consume()?;

        if token.kind == expected {
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken(token))
        }
    }


    fn parse_match(&mut self) -> Result<AstMatch, ParseError> {
        self.expect_keyword(KeywordType::Match)?;
        let kind = self.parse_ident()?;
        self.expect_token(TokenType::LBrace)?;
        let arms = self.parse_arms()?;
        self.expect_token(TokenType::RBrace)?;
        Ok(AstMatch { kind, arms })
    }

    fn parse_arms(&mut self) -> Result<Vec<AstArm>, ParseError> {
        let mut arms = Vec::new();
        while let Some(arm) = self.parse_arm()? {
            arms.push(arm); 
        }

        Ok(arms)
    }

    fn parse_arm(&mut self) -> Result<Option<AstArm>, ParseError> {
        if matches!(self.peek().map(|t| t.kind), Ok(TokenType::RBrace)) {
            return Ok(None)
        }

        let pattern = self.parse_pattern()?;
        self.expect_token(TokenType::Semicolon)?;
        let body = self.parse_body()?;

        Ok(Some(AstArm { pattern, body }))
    }

    fn parse_pattern(&mut self) -> Result<AstPattern, ParseError> {
        match self.peek()?.kind {
            TokenType::Pattern(PatternType::Or) => {
                self.consume()?;
                let mut patterns = Vec::new();
                loop {
                    patterns.push(self.parse_simple_pattern()?);
                    if !matches!(self.peek()?.kind, TokenType::Pattern(PatternType::Or)) {
                        break;
                    }
                    self.consume()?;
                }
                Ok(AstPattern::Or(patterns))
            }
            _ => self.parse_simple_pattern()
        }
    }

    // TODO: hacky workaround as we don't support nested combinator yet
    fn parse_simple_pattern(&mut self) -> Result<AstPattern, ParseError> {
        let token = self.consume()?;
        match token.kind {
            TokenType::Pattern(PatternType::Or) => {
                Err(ParseError::NestedCombinatorNotImplemented(token))
            }
            TokenType::Pattern(PatternType::Glob) => todo!(),
            TokenType::Pattern(PatternType::Equal) => {
                let value = self.parse_value()?;
                Ok(AstPattern::Equal(value))
            }
            TokenType::Pattern(PatternType::Greater) => {
                let value = self.parse_value()?;
                Ok(AstPattern::Greater(value))
            }
            TokenType::Pattern(PatternType::LesserOrEqual) => {
                let value = self.parse_value()?;
                Ok(AstPattern::LesserOrEqual(value))
            }
            _ => Err(ParseError::UnexpectedToken(token)),
        }
    }

    fn parse_operator(&mut self) -> Result<PatternType, ParseError> {
        let token = self.consume()?;

        match token.kind {
            TokenType::Pattern(p) => Ok(p), 
            _ => Err(ParseError::UnexpectedToken(token)),
        }
    }

    fn parse_value(&mut self) -> Result<AstValue, ParseError> {
        let token = self.consume()?;
        match token.kind {
            TokenType::Number(n) => Ok(AstValue::Number(n)),
            TokenType::StringLiteral(s) => Ok(AstValue::Str(s)),
            TokenType::Identifier(id) => Ok(AstValue::Ident(id)),
            _ => Err(ParseError::UnexpectedToken(token)),
        }
    }

    fn parse_body(&mut self) -> Result<AstBody, ParseError> {
        match self.peek()?.kind {
            TokenType::Keyword(KeywordType::Verdict) => {
                self.consume()?;
                let verdict = self.parse_ident()?;
                Ok(AstBody::Verdict(verdict))
            },
            TokenType::Keyword(KeywordType::Match) => {
                Ok(AstBody::Match(self.parse_match()?))
            },
            _ => {
                let token = self.consume()?;
                Err(ParseError::UnexpectedToken(token))
            }
        }
    }
    pub fn parse(&mut self) -> Result<AstMatch, ParseError> {
        self.parse_match()
    }
}
#[derive(Error, Debug, Display)]
enum ParseError {
    EmptyTokens,
    UnexpectedToken(Token),
    UnexpectedEndOfInput,
    NestedCombinatorNotImplemented(Token),
}
