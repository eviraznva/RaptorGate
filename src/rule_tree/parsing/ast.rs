use std::panic;

use derive_more::{Debug, Display};
use thiserror::Error;

use crate::rule_tree::parsing::lexer::{KeywordType, PatternType, Position, Token, TokenType};

#[derive(Debug, PartialEq)]
struct Spanned<T> {
    val: T,
    pos: Position,
}

#[derive(Debug, PartialEq)]
struct AstMatch {
    kind: Spanned<String>,
    arms: Spanned<Vec<AstArm>>,
}

#[derive(Debug, PartialEq)]
struct AstArm {
    pattern: Spanned<AstPattern>,
    body: Spanned<AstBody>,
}

#[derive(Debug, PartialEq)]
enum AstPattern {
    Equal(Spanned<AstValue>),
    Greater(Spanned<AstValue>),
    LesserOrEqual(Spanned<AstValue>),
    Range(Spanned<AstValue>, Spanned<AstValue>),
    Or(Spanned<Vec<AstPattern>>),
    Glob,
}

#[derive(Debug, PartialEq)]
enum AstValue {
    Number(Spanned<u64>),
    Str(Spanned<String>),
    Ident(Spanned<String>),
}

#[derive(Debug, PartialEq)]
enum AstBody {
    Verdict(Spanned<Verdict>),
    Match(Spanned<AstMatch>),
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Allow,
    Drop,
    AllowWarn(Spanned<String>),
    DropWarn(Spanned<String>),
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

    fn parse_ident(&mut self) -> Result<Spanned<String>, ParseError> {
        let token = self.consume()?;
        match token.kind {
            TokenType::Identifier(id) => Ok(Spanned { val: id, pos: token.pos }),
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


    fn parse_match(&mut self) -> Result<Spanned<AstMatch>, ParseError> {
        let start = self.consume()?;
        match start.kind {
            TokenType::Keyword(KeywordType::Match) => {}
            _ => return Err(ParseError::UnexpectedToken(start)),
        }
        let kind = self.parse_ident()?;
        self.expect_token(TokenType::LBrace)?;
        let arms = self.parse_arms()?;
        self.expect_token(TokenType::RBrace)?;
        Ok(Spanned {
            val: AstMatch { kind, arms: Spanned { val: arms, pos: start.pos } },
            pos: start.pos,
        })
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

    fn parse_pattern(&mut self) -> Result<Spanned<AstPattern>, ParseError> {
        match self.peek()?.kind {
            TokenType::Pattern(PatternType::Or) => {
                let or_tok = self.consume()?;
                let mut patterns = Vec::new();
                loop {
                    patterns.push(self.parse_simple_pattern()?.val);
                    match self.peek() {
                        Ok(t) if t.kind == TokenType::Pattern(PatternType::Or) => { self.consume()?; }
                        _ => break,
                    }
                }
                Ok(Spanned {
                    val: AstPattern::Or(Spanned { val: patterns, pos: or_tok.pos }),
                    pos: or_tok.pos,
                })
            }
            _ => self.parse_simple_pattern()
        }
    }

    fn parse_simple_pattern(&mut self) -> Result<Spanned<AstPattern>, ParseError> {
        let token = self.consume()?;
        match token.kind {
            TokenType::Pattern(PatternType::Or) => Err(ParseError::NestedCombinatorNotImplemented(token)),
            TokenType::Pattern(PatternType::Glob) => todo!(),
            TokenType::Pattern(PatternType::Equal) => {
                let value = self.parse_value()?;
                Ok(Spanned { val: AstPattern::Equal(value), pos: token.pos })
            }
            TokenType::Pattern(PatternType::Greater) => {
                let value = self.parse_value()?;
                Ok(Spanned { val: AstPattern::Greater(value), pos: token.pos })
            }
            TokenType::Pattern(PatternType::LesserOrEqual) => {
                let value = self.parse_value()?;
                Ok(Spanned { val: AstPattern::LesserOrEqual(value), pos: token.pos })
            }
            _ => Err(ParseError::UnexpectedToken(token)),
        }
    }

    fn parse_value(&mut self) -> Result<Spanned<AstValue>, ParseError> {
        let token = self.consume()?;
        match token.kind {
            TokenType::Number(n) => Ok(Spanned { val: AstValue::Number(Spanned { val: n, pos: token.pos }), pos: token.pos }),
            TokenType::StringLiteral(s) => Ok(Spanned { val: AstValue::Str(Spanned { val: s, pos: token.pos }), pos: token.pos }),
            TokenType::Identifier(id) => Ok(Spanned { val: AstValue::Ident(Spanned { val: id, pos: token.pos }), pos: token.pos }),
            _ => Err(ParseError::UnexpectedToken(token)),
        }
    }

    fn parse_body(&mut self) -> Result<Spanned<AstBody>, ParseError> {
        match self.peek()?.kind {
            TokenType::Keyword(KeywordType::Verdict) => {
                let kw = self.consume()?;
                let verdict = self.parse_verdict()?;
                Ok(Spanned { val: AstBody::Verdict(verdict), pos: kw.pos })
            },
            TokenType::Keyword(KeywordType::Match) => {
                let m = self.parse_match()?;
                let pos = m.pos;
                Ok(Spanned { val: AstBody::Match(m), pos })
            },
            _ => {
                let token = self.consume()?;
                Err(ParseError::UnexpectedToken(token))
            }
        }
    }

    fn parse_verdict(&mut self) -> Result<Spanned<Verdict>, ParseError> {
        let token = self.consume()?;
        match &token.kind {
            TokenType::Identifier(id) => match id.as_str() {
                "allow" => Ok(Spanned { val: Verdict::Allow, pos: token.pos }),
                "drop" => Ok(Spanned { val: Verdict::Drop, pos: token.pos }),
                "allow_warn" => {
                    let msg = self.parse_value()?;
                    if let AstValue::Str(s) = msg.val {
                        Ok(Spanned { val: Verdict::AllowWarn(s), pos: token.pos })
                    } else {
                        Err(ParseError::UnexpectedToken(token))
                    }
                },
                "drop_warn" => {
                    let msg = self.parse_value()?;
                    if let AstValue::Str(s) = msg.val {
                        Ok(Spanned { val: Verdict::DropWarn(s), pos: token.pos })
                    } else {
                        Err(ParseError::UnexpectedToken(token))
                    }
                },
                _ => Err(ParseError::UnexpectedToken(token)),
            }
            _ => Err(ParseError::UnexpectedToken(token)),
        }
    }

    pub fn parse(&mut self) -> Result<Spanned<AstMatch>, ParseError> {
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

    // test helpers (ignore spans, check payload only)
    fn is_ident(v: &AstValue, expected: &str) -> bool {
        matches!(v, AstValue::Ident(s) if s.val == expected)
    }

    fn is_number(v: &AstValue, expected: u64) -> bool {
        matches!(v, AstValue::Number(n) if n.val == expected)
    }

    fn is_equal_ident(p: &AstPattern, expected: &str) -> bool {
        matches!(p, AstPattern::Equal(v) if is_ident(&v.val, expected))
    }

    fn is_equal_number(p: &AstPattern, expected: u64) -> bool {
        matches!(p, AstPattern::Equal(v) if is_number(&v.val, expected))
    }

    fn is_greater_number(p: &AstPattern, expected: u64) -> bool {
        matches!(p, AstPattern::Greater(v) if is_number(&v.val, expected))
    }

    // ---- parse_value -------------------------------------------------------

    #[test]
    fn parse_value_number() {
        let mut p = Parser::new(vec![tok(TokenType::Number(42))]);
        assert_eq!(p.parse_value().unwrap().val, AstValue::Number(Spanned { val: 42, pos: Position::for_tests(1.into(), 1.into()) }));
    }

    #[test]
    fn parse_value_string() {
        let mut p = Parser::new(vec![tok(TokenType::StringLiteral("hello".into()))]);
        assert!(matches!(p.parse_value().unwrap().val, AstValue::Str(s) if s.val == "hello"));
    }

    #[test]
    fn parse_value_ident() {
        let mut p = Parser::new(vec![tok(TokenType::Identifier("tcp".into()))]);
        assert!(matches!(p.parse_value().unwrap().val, AstValue::Ident(s) if s.val == "tcp"));
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
        assert!(matches!(p.parse_simple_pattern().unwrap().val, AstPattern::Equal(v) if matches!(&v.val, AstValue::Str(s) if s.val == "tcp")));
    }

    #[test]
    fn parse_simple_pattern_equal_number() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Equal)),
            tok(TokenType::Number(80)),
        ]);
        let pat = p.parse_simple_pattern().unwrap();
        assert!(is_equal_number(&pat.val, 80));
    }

    #[test]
    fn parse_simple_pattern_greater() {
        let mut p = Parser::new(vec![
            tok(TokenType::Pattern(PatternType::Greater)),
            tok(TokenType::Number(1024)),
        ]);
        let pat = p.parse_simple_pattern().unwrap();
        assert!(is_greater_number(&pat.val, 1024));
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

        let pat = p.parse_pattern().unwrap();
        match pat.val {
            AstPattern::Or(v) => {
                assert_eq!(v.val.len(), 2);
                assert!(is_equal_ident(&v.val[0], "tcp"));
                assert!(is_equal_ident(&v.val[1], "udp"));
            }
            _ => panic!("expected Or pattern"),
        }
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

        let pat = p.parse_pattern().unwrap();
        match pat.val {
            AstPattern::Or(v) => {
                assert_eq!(v.val.len(), 3);
                assert!(is_equal_ident(&v.val[0], "tcp"));
                assert!(is_equal_ident(&v.val[1], "udp"));
                assert!(is_equal_ident(&v.val[2], "icmp"));
            }
            _ => panic!("expected Or pattern"),
        }
    }

    // ---- parse_body --------------------------------------------------------

    #[test]
    fn parse_body_verdict() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow".into())),
        ]);
        assert!(matches!(p.parse_body().unwrap().val, AstBody::Verdict(v) if matches!(v.val, Verdict::Allow)));
    }

    #[test]
    fn parse_body_verdict_warn() {
        let mut p = Parser::new(vec![
            tok(TokenType::Keyword(KeywordType::Verdict)),
            tok(TokenType::Identifier("allow_warn".into())),
            tok(TokenType::StringLiteral("allow warn message".into())),
        ]);
        assert!(matches!(p.parse_body().unwrap().val, AstBody::Verdict(v) if matches!(&v.val, Verdict::AllowWarn(s) if s.val == "allow warn message")));
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
        let arm = p.parse_arm().unwrap().unwrap();
        assert!(matches!(arm.pattern.val, AstPattern::Equal(v) if matches!(&v.val, AstValue::Ident(s) if s.val == "v4")));
        assert!(matches!(arm.body.val, AstBody::Verdict(v) if matches!(v.val, Verdict::Allow)));
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
        let ast = p.parse_match().unwrap();
        assert_eq!(ast.val.kind.val, "protocol");
        assert_eq!(ast.val.arms.val.len(), 1);
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
        assert_eq!(ast.val.kind.val, "protocol");
        assert_eq!(ast.val.arms.val.len(), 2);
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
        assert_eq!(ast.val.kind.val, "ip_ver");
        assert!(matches!(
            ast.val.arms.val[0].body.val,
            AstBody::Match(ref m) if m.val.kind.val == "protocol"
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
        assert_eq!(ast.val.arms.val.len(), 2);
        assert!(matches!(&ast.val.arms.val[0].pattern.val, AstPattern::Or(v) if v.val.len() == 2));
        assert!(matches!(&ast.val.arms.val[1].body.val, AstBody::Match(_)));
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
