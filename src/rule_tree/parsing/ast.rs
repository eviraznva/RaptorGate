use std::panic;

use derive_more::{Debug, Display};
use thiserror::Error;

use crate::rule_tree::parsing::lexer::{KeywordType, PatternType, Token, TokenType};

#[derive(Debug, PartialEq)]
struct AstMatch {
    kind: String,
    arms: Vec<AstArm>,
}

#[derive(Debug, PartialEq)]
struct AstArm {
    pattern: AstPattern,
    body: AstBody,
}

#[derive(Debug, PartialEq)]
enum AstPattern {
    Equal(AstValue),
    Greater(AstValue),
    LesserOrEqual(AstValue),
    Range(AstValue, AstValue),
    Or(Vec<AstPattern>),
    Glob,
}

#[derive(Debug, PartialEq)]
enum AstValue {
    Number(u64),
    Str(String),
    Ident(String),
}

#[derive(Debug, PartialEq)]
enum AstBody {
    Verdict(Verdict),
    Match(AstMatch),
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Allow,
    Drop,
    AllowWarn(String),
    DropWarn(String),
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
        self.expect_token(TokenType::Colon)?;
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
                    match self.peek() {
                        Ok(t) if t.kind == TokenType::Pattern(PatternType::Or) => { self.consume()?; }
                        _ => break,
                    }
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
        //TODO: figure out consisten peeking and consuming rules
        match self.peek()?.kind {
            TokenType::Keyword(KeywordType::Verdict) => {
                self.consume()?;
                let verdict = self.parse_verdict()?;
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

    fn parse_verdict(&mut self) -> Result<Verdict, ParseError> {
        let token = self.consume()?;
        match &token.kind {
            TokenType::Identifier(id) => match id.as_str() {
                "allow" => Ok(Verdict::Allow),
                "drop" => Ok(Verdict::Drop),
                "allow_warn" => {
                    let msg = self.parse_value()?;
                    if let AstValue::Str(s) = msg {
                        Ok(Verdict::AllowWarn(s))
                    } else {
                        Err(ParseError::UnexpectedToken(token))
                    }
                },

                "drop_warn" => {
                    let msg = self.parse_value()?;
                    if let AstValue::Str(s) = msg {
                        Ok(Verdict::DropWarn(s))
                    } else {
                        Err(ParseError::UnexpectedToken(token))
                    }
                },

                _ => Err(ParseError::UnexpectedToken(token)),
            }
            _ => Err(ParseError::UnexpectedToken(token)),
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

#[cfg(test)]
mod tests {
    use crate::rule_tree::parsing::lexer::Position;

    use super::*;

    fn tok(kind: TokenType) -> Token {
        Token::for_tests(kind, Position::for_tests(1.into(), 1.into()))
    }

    // ---- parse_value -------------------------------------------------------

    #[test]
    fn parse_value_number() {
        let mut p = Parser::new(vec![tok(TokenType::Number(42))]);
        assert_eq!(p.parse_value().unwrap(), AstValue::Number(42));
    }

    #[test]
    fn parse_value_string() {
        let mut p = Parser::new(vec![tok(TokenType::StringLiteral("hello".into()))]);
        assert_eq!(p.parse_value().unwrap(), AstValue::Str("hello".into()));
    }

    #[test]
    fn parse_value_ident() {
        let mut p = Parser::new(vec![tok(TokenType::Identifier("tcp".into()))]);
        assert_eq!(p.parse_value().unwrap(), AstValue::Ident("tcp".into()));
    }

    #[test]
    fn parse_value_unexpected_token() {
        let mut p = Parser::new(vec![tok(TokenType::LBrace)]);
        assert!(matches!(p.parse_value(), Err(ParseError::UnexpectedToken(_))));
    }

    // ---- parse_simple_pattern ----------------------------------------------

    #[test]
    fn parse_simple_pattern_equal_string() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::StringLiteral("tcp".into())),
        ]);
        assert_eq!(
            p.parse_simple_pattern().unwrap(),
            AstPattern::Equal(AstValue::Str("tcp".into()))
        );
    }

    #[test]
    fn parse_simple_pattern_equal_number() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Number(80)),
        ]);
        assert_eq!(
            p.parse_simple_pattern().unwrap(),
            AstPattern::Equal(AstValue::Number(80))
        );
    }

    #[test]
    fn parse_simple_pattern_greater() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Greater)),
            tok(TokenType::Number(1024)),
        ]);
        assert_eq!(
            p.parse_simple_pattern().unwrap(),
            AstPattern::Greater(AstValue::Number(1024))
        );
    }

    #[test]
    fn parse_simple_pattern_rejects_nested_or() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Or)),
        ]);
        assert!(matches!(
            p.parse_simple_pattern(),
            Err(ParseError::NestedCombinatorNotImplemented(_))
        ));
    }

    // ---- parse_pattern (Or) ------------------------------------------------

    #[test]
    fn parse_pattern_or_two_values() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Or)),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("tcp".into())),
            tok(TokenType::Pattern(PatternType::Or)),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("udp".into())),
        ]);
        assert_eq!(
            p.parse_pattern().unwrap(),
            AstPattern::Or(vec![
                AstPattern::Equal(AstValue::Ident("tcp".into())),
                AstPattern::Equal(AstValue::Ident("udp".into())),
            ])
        );
    }

    #[test]
    fn parse_pattern_or_three_values() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Or)),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("tcp".into())),
            tok(TokenType::Pattern(PatternType::Or)),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("udp".into())),
            tok(TokenType::Pattern(PatternType::Or)),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("icmp".into())),
        ]);
        assert_eq!(
            p.parse_pattern().unwrap(),
            AstPattern::Or(vec![
                AstPattern::Equal(AstValue::Ident("tcp".into())),
                AstPattern::Equal(AstValue::Ident("udp".into())),
                AstPattern::Equal(AstValue::Ident("icmp".into())),
            ])
        );
    }

    // ---- parse_body --------------------------------------------------------

    #[test]
    fn parse_body_verdict() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow".into())),
        ]);
        assert_eq!(p.parse_body().unwrap(), AstBody::Verdict(Verdict::Allow));
    }

    #[test]
    fn parse_body_verdict_warn() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow_warn".into())),
            tok(TokenType::StringLiteral("allow warn message".into())),
        ]);
        assert_eq!(p.parse_body().unwrap(), AstBody::Verdict(Verdict::AllowWarn("allow warn message".into())));
    }

    #[test]
    fn parse_body_verdict_unexpected_message() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow_warn".into())),
            tok(TokenType::Number(5)),
        ]);
        assert!(matches!(p.parse_body(), Err(ParseError::UnexpectedToken(_))));
    }

    #[test]
    fn parse_body_unexpected_token() {
        let mut p = Parser::new(vec![tok(TokenType::Number(5))]);
        assert!(matches!(p.parse_body(), Err(ParseError::UnexpectedToken(_))));
    }

    // ---- parse_arm ---------------------------------------------------------

    #[test]
    fn parse_arm_simple() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("v4".into())),
            tok(TokenType::Colon),
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow".into())),
        ]);
        assert_eq!(
            p.parse_arm().unwrap(),
            Some(AstArm {
                pattern: AstPattern::Equal(AstValue::Ident("v4".into())),
                body: AstBody::Verdict(Verdict::Allow),
            })
        );
    }

    #[test]
    fn parse_arm_returns_none_on_rbrace() {
        let mut p = Parser::new(vec![tok(TokenType::RBrace)]);
        assert_eq!(p.parse_arm().unwrap(), None);
    }

    // ---- parse_match -------------------------------------------------------

    #[test]
    fn parse_match_single_arm() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("protocol".into())),
            tok(TokenType::LBrace),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("tcp".into())),
            tok(TokenType::Colon),
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow".into())),
            tok(TokenType::RBrace),
        ]);
        assert_eq!(
            p.parse_match().unwrap(),
            AstMatch {
                kind: "protocol".into(),
                arms: vec![AstArm {
                    pattern: AstPattern::Equal(AstValue::Ident("tcp".into())),
                    body: AstBody::Verdict(Verdict::Allow),
                }]
            }
        );
    }

    #[test]
    fn parse_match_multiple_arms() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("protocol".into())),
            tok(TokenType::LBrace),
            // arm 1: = "tcp" : verdict allow
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("tcp".into())),
            tok(TokenType::Colon),
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow".into())),
            // arm 2: = "udp" : verdict drop
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("udp".into())),
            tok(TokenType::Colon),
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("drop".into())),
            tok(TokenType::RBrace),
        ]);
        let ast = p.parse_match().unwrap();
        assert_eq!(ast.kind, "protocol");
        assert_eq!(ast.arms.len(), 2);
    }

    #[test]
    fn parse_match_nested() {
        // match ip_ver {
        //     = v4 : match protocol {
        //         = "tcp" : verdict allow
        //     }
        // }
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("ip_ver".into())),
            tok(TokenType::LBrace),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("v4".into())),
            tok(TokenType::Colon),
            // nested match
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("protocol".into())),
            tok(TokenType::LBrace),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("tcp".into())),
            tok(TokenType::Colon),
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow".into())),
            tok(TokenType::RBrace),
            // end outer
            tok(TokenType::RBrace),
        ]);
        let ast = p.parse_match().unwrap();
        assert_eq!(ast.kind, "ip_ver");
        assert!(matches!(
            ast.arms[0].body,
            AstBody::Match(AstMatch { ref kind, .. }) if kind == "protocol"
        ));
    }

    #[test]
    fn parse_match_or_pattern_with_nested_match() {
        // match protocol {
        //     | = "tcp" | = "udp" : verdict allow
        //     = "icmp"            : match dst_port {
        //         > 1024 : verdict drop
        //     }
        // }
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("protocol".into())),
            tok(TokenType::LBrace),
            // arm 1: or pattern
            tok(TokenType::Pattern(PatternType::Or)),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("tcp".into())),
            tok(TokenType::Pattern(PatternType::Or)),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("udp".into())),
            tok(TokenType::Colon),
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow".into())),
            // arm 2: nested match
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("icmp".into())),
            tok(TokenType::Colon),
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("dst_port".into())),
            tok(TokenType::LBrace),
            tok(TokenType::Pattern(PatternType::Greater)),
            tok(TokenType::Number(1024)),
            tok(TokenType::Colon),
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("drop".into())),
            tok(TokenType::RBrace),
            tok(TokenType::RBrace),
        ]);
        let ast = p.parse_match().unwrap();
        assert_eq!(ast.arms.len(), 2);
        assert!(matches!(&ast.arms[0].pattern, AstPattern::Or(v) if v.len() == 2));
        assert!(matches!(&ast.arms[1].body, AstBody::Match(_)));
    }

    // ---- error cases -------------------------------------------------------

    #[test]
    fn parse_match_missing_lbrace() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("protocol".into())),
            // missing LBrace
            tok(TokenType::Pattern(PatternType::Equal)),
        ]);
        assert!(matches!(p.parse_match(), Err(ParseError::UnexpectedToken(_))));
    }

    #[test]
    fn parse_match_eof_inside_arms() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("protocol".into())),
            tok(TokenType::LBrace),
            // no arms, no RBrace — just EOF
        ]);
        assert!(matches!(p.parse_match(), Err(ParseError::UnexpectedEndOfInput)));
    }

    #[test]
    fn parse_match_missing_semicolon_in_arm() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Match)),
            tok(TokenType::Identifier("protocol".into())),
            tok(TokenType::LBrace),
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Identifier("tcp".into())),
            // missing Semicolon — goes straight to verdict
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow".into())),
            tok(TokenType::RBrace),
        ]);
        assert!(matches!(p.parse_match(), Err(ParseError::UnexpectedToken(_))));
    }
}
