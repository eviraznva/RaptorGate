use std::{char, fmt::Display, thread::current};
use paste::paste;

use derive_more::{Add, AddAssign, Debug, Display, From, derive};
use thiserror::Error;

macro_rules! separating_chars {
    () => {
        '{' | '}' | '|' | '<' | '>' | '=' | ':'
    };
}

#[derive(Error, Debug, Display)]
pub(crate) enum LexerError {
    UnclosedStringLiteral(Position)
}

enum LexerMode {
    Normal,
    StringLiteral(StringLiteralBuilder),
}

struct StringLiteralBuilder {
    start_pos: Position,
    contents: String,
}

impl StringLiteralBuilder {
    fn push(&mut self, word: char) {
        self.contents.push(word); 
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Position {
    row: Row,
    col: Col,
}

impl Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.row.0, self.col.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Token {
    pos: Position,
    kind: TokenType,
}

#[derive(Debug, Clone, Copy, From, Add, AddAssign, PartialEq)]
struct Row(usize);

#[derive(Debug, Clone, Copy, From, Add, AddAssign, PartialEq)]
struct Col(usize);

#[derive(Debug, Clone, PartialEq)]
enum TokenType {
    Identifier(String),
    Number(u64),
    Pattern(PatternType),
    StringLiteral(String),
    Keyword(KeywordType),
    LBrace,
    RBrace,
}

#[derive(Debug, Clone, PartialEq)]
enum KeywordType {
    Match,
    Verdict
}

#[derive(Debug, Clone, PartialEq)]
enum PatternType {
    Equal,
    Lesser,
    Greater,
    LesserOrEqual,
    GreaterOrEqual,
    Or,
    Range,
    Glob,
}

#[derive(Debug, Clone)]
struct Word {
    contents: String,
    start_pos: Position,
}

impl Word {
    fn new(contents: String, pos: Position) -> Self {
        Self { contents, start_pos: pos }
    }

    fn default() -> Self {
        Self { contents: "".into(), start_pos: Position { row: 0.into(), col: 0.into() } }
    }

    fn push(&mut self, c: char) {
        self.contents.push(c);
    }

    fn into_token(&self, kind: TokenType) -> Token {
        Token { pos: self.start_pos, kind }
    }
}

struct WordBuilder {
    current_word: String,
    start_pos: Position,
}


impl WordBuilder {
    fn new() -> Self {
        Self { current_word: String::new(), start_pos: Position { row: 0.into(), col: 0.into() } }
    }

    fn add_to(&mut self, c: char, pos: Position) -> Option<Word> {
        if self.current_word.is_empty()  {
            if c.is_whitespace() {
                return None
            }

            self.start_pos = pos;
            self.current_word.push(c);
        } else {
            if c.is_whitespace() {
                return Some(self.exchange(c, pos))
            }

            if matches!(self.current_word.as_str(), "<=" | ">=" | "<>") {
                return Some(self.exchange(c, pos))
            }

            if matches!(c, separating_chars!())
                && (self.current_word.starts_with('<') || self.current_word.starts_with('>')) {
                    let expected = if self.current_word.starts_with('>') { '<' } else { '>' };
                    
                    if c == '=' || c == expected {
                        self.current_word.push(c);
                    }

                    return Some(self.exchange(c, pos))
                }
        }

        None
    }

    fn exchange(&mut self, c: char, pos: Position) -> Word {
        let word = self.current_word.clone();
        let old_pos = self.start_pos;
        self.current_word = c.into();
        self.current_word = self.current_word.trim().into();
        self.start_pos = pos;

        Word::new(word, old_pos)
    }
}

pub(crate) struct Lexer {
    mode: LexerMode,
    curret_pos: Position,
    word_builder: WordBuilder,
}

impl Lexer {
    pub fn new() -> Self {
        Self { mode: LexerMode::Normal, curret_pos: Position { row: 0.into(), col: 0.into() }, word_builder: WordBuilder::new() }
    }

    fn update_pos(&mut self, current_char: char) {
        if current_char == '\n' {
            self.curret_pos.row += 1.into();
            self.curret_pos.col = 0.into();
            return;
        }

        self.curret_pos.col += 1.into();
    }

    pub(crate) fn tokenize(&mut self, input: &str) -> Result<Vec<Token>, LexerError> {
        let mut tokens = Vec::<Token>::new();

        for c in input.chars() {
            self.update_pos(c);

            match &mut self.mode {
                LexerMode::Normal => {
                    if c == '\"' {
                        self.mode = LexerMode::StringLiteral(StringLiteralBuilder { start_pos: self.curret_pos, contents: String::new() });
                        continue;
                    }

                    let Some(word) = self.word_builder.add_to(c, self.curret_pos) else { continue };

                    tokens.push(
                        match word.contents.as_str() {
                            "=" => word.into_token(TokenType::Pattern(PatternType::Equal)),
                            "<" => word.into_token(TokenType::Pattern(PatternType::Lesser)),
                            ">" => word.into_token(TokenType::Pattern(PatternType::Greater)),
                            "<=" => word.into_token(TokenType::Pattern(PatternType::LesserOrEqual)),
                            ">=" => word.into_token(TokenType::Pattern(PatternType::GreaterOrEqual)),
                            "_" => word.into_token(TokenType::Pattern(PatternType::Glob)),
                            "|" => word.into_token(TokenType::Pattern(PatternType::Or)),
                            "<>" => word.into_token(TokenType::Pattern(PatternType::Range)),
                            "{" => word.into_token(TokenType::LBrace),
                            "}" => word.into_token(TokenType::RBrace),
                            _ => word.into_token(TokenType::Identifier(word.contents.clone())),
                        }
                    );
                },
                LexerMode::StringLiteral(sb) => {
                    if c == '\"' {
                        tokens.push(Token { pos: sb.start_pos, kind: TokenType::StringLiteral(sb.contents.clone()) });
                        self.mode = LexerMode::Normal;
                        continue;
                    }

                    sb.push(c);
                },
            }
        }

        if let LexerMode::StringLiteral(sb) = &self.mode { return Err(LexerError::UnclosedStringLiteral(sb.start_pos)) }

        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::rule_tree::lexer::{LexerError, Lexer, PatternType, Position, Token, TokenType};

    #[test]
    fn empty_ruleset_passes() {
        let stream = "";
        let mut lexer = Lexer::new();

        assert!(lexer.tokenize(stream).is_ok());
    }

    macro_rules! gen_space_tests {
        ($name:ident, $stream_space:expr, $expected:expr) => {
            paste::paste! {
                #[test]
                fn [<$name _no_space>]() {
                    let mut lexer = Lexer::new();
                    let mut s = String::from($stream_space);
                    s.retain(|c| !c.is_whitespace());
                    let got: Vec<TokenType> = lexer
                        .tokenize(&s)
                        .unwrap()
                        .into_iter()
                        .map(|t| t.kind)
                        .collect();
                    assert_eq!(got, $expected);
                }
                #[test]
                fn [<$name _space>]() {
                    let mut lexer = Lexer::new();
                    let got: Vec<TokenType> = lexer
                        .tokenize($stream_space)
                        .unwrap()
                        .into_iter()
                        .map(|t| t.kind)
                        .collect();
                    assert_eq!(got, $expected);
                }
            }
        };
    }

    gen_space_tests!(
        le_operator,
        "5 < abc",
        vec![
            TokenType::Identifier("5".into()),
            TokenType::Pattern(PatternType::Lesser),
            TokenType::Identifier("abc".into()),
        ]
    );

    gen_space_tests!(
        leq_operator,
        "5 < abc",
        vec![
            TokenType::Identifier("5".into()),
            TokenType::Pattern(PatternType::Lesser),
            TokenType::Identifier("abc".into()),
        ]
    );
    
    gen_space_tests!(
        rng_operator,
        "5 <> abc",
        vec![
            TokenType::Identifier("5".into()),
            TokenType::Pattern(PatternType::Lesser),
            TokenType::Identifier("abc".into()),
        ]
    );

    #[test]
    fn string_literal_no_space() {
        let mut lexer = Lexer::new();
        let mut s = String::from("abd efgh");
        s.retain(|c| !c.is_whitespace());
        let got: Vec<TokenType> = lexer
            .tokenize(&s)
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect();
        assert_eq!(got, vec![TokenType::StringLiteral("abdefgh".into())]);
    }

    #[test]
    fn string_literal_space() {
        let mut lexer = Lexer::new();
        let got: Vec<TokenType> = lexer
            .tokenize("abd efgh")
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect();
        assert_eq!(got, vec![TokenType::StringLiteral("abd efgh".into())]);
    }

    #[test]
    fn string_literals_dont_shadow_idents() {
        let mut lexer = Lexer::new();
        let got: Vec<TokenType> = lexer
            .tokenize("abc\"adsf\"dfgh")
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect();
        assert_eq!(
            got,
            vec![
                TokenType::Identifier("abc".into()),
                TokenType::StringLiteral("adsf".into()),
                TokenType::Identifier("dfgh".into()),
            ]
        );
    }

    #[test]
    fn special_chars_dont_break_string_literals_no_space(){
        let mut lexer = Lexer::new();
        let mut s = String::from("abc { dfg } xd {} dx <");
        s.retain(|c| !c.is_whitespace());
        let got:Vec<TokenType>  = lexer.tokenize(&s).unwrap().into_iter().map(|t|t.kind).collect();
        assert_eq!(got,(vec![TokenType::StringLiteral("abc{dfg}xd{}dx<".into())]));
    }

    #[test]
    fn special_chars_dont_break_string_literals_space(){
        let mut lexer = Lexer::new();
        let got:Vec<TokenType>  = lexer.tokenize("abc { dfg } xd {} dx <").unwrap().into_iter().map(|t|t.kind).collect();
        assert_eq!(got,(vec![TokenType::StringLiteral("abc { dfg } xd {} dx <".into())]));
    }

}
