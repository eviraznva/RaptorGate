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

#[cfg(test)]
impl Position {
    pub fn for_tests(row: Row, col: Col) -> Self {
        Position { row, col }
    } 
}

#[derive(Debug, Clone, Copy, From, Add, AddAssign, PartialEq)]
#[cfg_attr(test, visibility::make(pub))]
pub struct Row(usize);

#[derive(Debug, Clone, Copy, From, Add, AddAssign, PartialEq)]
#[cfg_attr(test, visibility::make(pub))]
struct Col(usize);



impl Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.row.0, self.col.0)
    }
}

#[derive(Debug, Clone, PartialEq, Display)]
#[display("{}: {}", pos, kind)]
pub(super)struct Token {
    pub(super) pos: Position,
    pub(super) kind: TokenType,
}
impl Token {
    #[cfg(test)]
    pub(crate) fn for_tests(kind: TokenType, pos: Position) -> Self {
        Self { pos, kind }
    }
}
#[derive(Debug, Clone, PartialEq, Display)]
pub(super) enum TokenType {
    Identifier(String),
    Number(u64),
    Pattern(PatternType),
    StringLiteral(String),
    Keyword(KeywordType),
    LBrace,
    RBrace,
    Colon,
}

#[derive(Debug, Clone, PartialEq, Display)]
pub(super) enum KeywordType {
    Match,
    Verdict
}

#[derive(Debug, Clone, PartialEq, Display)]
pub(super) enum PatternType {
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

            if self.current_word.starts_with('<') || self.current_word.starts_with('>') {
                let expected = if self.current_word.starts_with('>') { '<' } else { '>' };

                if c == '=' || c == expected {
                    self.current_word.push(c);
                    return Some(self.exchange(' ', pos))
                }

                return Some(self.exchange(c, pos))
            }

            if self.current_word.len() == 1
                && matches!(self.current_word.chars().next(), Some(separating_chars!()))
            {
                return Some(self.exchange(c, pos))
            }

            if matches!(c, separating_chars!()) {
                return Some(self.exchange(c, pos))
            }

            self.current_word.push(c);
        }

        None
    }

    fn flush(&mut self) -> Option<Word> {
        if self.current_word.is_empty() { return None }
        Some(self.exchange(' ', self.start_pos))
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
        Self { mode: LexerMode::Normal, curret_pos: Position { row: 1.into(), col: 0.into() }, word_builder: WordBuilder::new() }
    }

    fn update_pos(&mut self, current_char: char) {
        if current_char == '\n' {
            self.curret_pos.row += 1.into();
            self.curret_pos.col = 0.into();
            return;
        }

        self.curret_pos.col += 1.into();
    }

    fn classify(word: Word) -> Token {
        if let Ok(n) = word.contents.parse::<u64>() {
            return word.into_token(TokenType::Number(n));
        }

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
            ":" => word.into_token(TokenType::Colon),
            "match" => word.into_token(TokenType::Keyword(KeywordType::Match)),
            "verdict" => word.into_token(TokenType::Keyword(KeywordType::Verdict)),
            _ => word.into_token(TokenType::Identifier(word.contents.clone())),
        }
    }

    pub(crate) fn tokenize(&mut self, input: &str) -> Result<Vec<Token>, LexerError> {
        let mut tokens = Vec::<Token>::new();

        for c in input.chars() {
            self.update_pos(c);
            match &mut self.mode {
                LexerMode::Normal => {
                    if c == '\"' {
                        if let Some(word) = self.word_builder.flush() { tokens.push(Self::classify(word)) }
                        self.mode = LexerMode::StringLiteral(StringLiteralBuilder { start_pos: self.curret_pos, contents: String::new() });
                        continue;
                    }

                    let Some(word) = self.word_builder.add_to(c, self.curret_pos) else { continue };

                    tokens.push(
                        Self::classify(word)
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

        match &self.mode {
            LexerMode::StringLiteral(sb) => return Err(LexerError::UnclosedStringLiteral(sb.start_pos)),
            LexerMode::Normal => {
                if let Some(word) = self.word_builder.flush() { tokens.push(Self::classify(word)) }
            }
        }
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::rule_tree::parsing::lexer::{KeywordType, Lexer, LexerError, PatternType, Position, Token, TokenType};

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
        ($name:ident, $stream_space:expr, $expected:expr, $disable_no_space:ident) => {
            paste::paste! {
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

    macro_rules! gen_position_tests {
        ($name:ident, $stream:expr, $expected:expr) => {
            paste::paste! {
                #[test]
                fn [<$name _positions_space>]() {
                    let mut lexer = Lexer::new();
                    let got: Vec<Position> = lexer
                        .tokenize($stream)
                        .unwrap()
                        .into_iter()
                        .map(|t| t.pos)
                        .collect();
                    assert_eq!(got, $expected);
                }

                #[test]
                fn [<$name _positions_no_space>]() {
                    let mut lexer = Lexer::new();
                    let mut s = String::from($stream);
                    s.retain(|c| !c.is_whitespace());

                    let got: Vec<Position> = lexer
                        .tokenize(&s)
                        .unwrap()
                        .into_iter()
                        .map(|t| t.pos)
                        .collect();

                    let expected: Vec<Position> = (0..got.len())
                        .map(|i| Position { row: 1.into(), col: (i + 1).into() })
                        .collect();

                    assert_eq!(got, expected);
                }
            }
        };
    }

    gen_space_tests!(
        le_operator,
        "5 < abc",
        vec![
            TokenType::Number(5),
            TokenType::Pattern(PatternType::Lesser),
            TokenType::Identifier("abc".into()),
        ]
    );

    gen_space_tests!(
        left_ge_operator,
        "> 5",
        vec![
            TokenType::Pattern(PatternType::Greater),
            TokenType::Number(5),
        ]
    );

    gen_space_tests!(
        left_geq_operator,
        ">= 5",
        vec![
            TokenType::Pattern(PatternType::GreaterOrEqual),
            TokenType::Number(5),
        ]
    );

    gen_space_tests!(
        leq_operator,
        "5 <= abc",
        vec![
            TokenType::Number(5),
            TokenType::Pattern(PatternType::LesserOrEqual),
            TokenType::Identifier("abc".into()),
        ]
    );
    
    gen_space_tests!(
        rng_operator,
        "5 <> abc",
        vec![
            TokenType::Number(5),
            TokenType::Pattern(PatternType::Range),
            TokenType::Identifier("abc".into()),
        ]
    );
    gen_space_tests!(
        ge_operator,
        "5 > abc",
        vec![
            TokenType::Number(5),
            TokenType::Pattern(PatternType::Greater),
            TokenType::Identifier("abc".into()),
        ]
    );

    gen_space_tests!(
        geq_operator,
        "5 >= abc",
        vec![
            TokenType::Number(5),
            TokenType::Pattern(PatternType::GreaterOrEqual),
            TokenType::Identifier("abc".into()),
        ]
    );

    gen_space_tests!(
        eq_operator,
        "5 = abc",
        vec![
            TokenType::Number(5),
            TokenType::Pattern(PatternType::Equal),
            TokenType::Identifier("abc".into()),
        ]
    );

    gen_space_tests!(
        or_operator,
        "5 | abc",
        vec![
            TokenType::Number(5),
            TokenType::Pattern(PatternType::Or),
            TokenType::Identifier("abc".into()),
        ]
    );

    gen_space_tests!(
        colon_separator_alphanum,
        "ip : 255",
        vec![
            TokenType::Identifier("ip".into()),
            TokenType::Colon,
            TokenType::Number(255),
        ]
    );

    gen_space_tests!(
        colon_separator_braces_partial,
        "ip : {",
        vec![
            TokenType::Identifier("ip".into()),
            TokenType::Colon,
            TokenType::LBrace,
        ]
    );

    gen_space_tests!(
        colon_separator_braces_full,
        "} : {",
        vec![
            TokenType::RBrace,
            TokenType::Colon,
            TokenType::LBrace,
        ]
    );

    gen_space_tests!(
        keyword_match,
        "match ip {",
        vec![
            TokenType::Keyword(KeywordType::Match),
            TokenType::Identifier("ip".into()),
            TokenType::LBrace,
        ],
        disable
    );

    gen_space_tests!(
        keyword_verdict,
        "verdict allow",
        vec![
            TokenType::Keyword(KeywordType::Verdict),
            TokenType::Identifier("allow".into()),
        ],
        disable
    );

    gen_space_tests!(
        keyword_verdict_warn,
        "verdict allow_warn \"allow message\"",
        vec![
            TokenType::Keyword(KeywordType::Verdict),
            TokenType::Identifier("allow_warn".into()),
            TokenType::StringLiteral("allow message".into()),
        ],
        disable
    );

    #[test]
    fn string_literal_no_space() {
        let mut lexer = Lexer::new();
        let mut s = String::from("\"abd efgh\"");
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
            .tokenize("\"abd efgh\"")
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
        let mut s = String::from("\"abc { dfg } xd {} dx <\"");
        s.retain(|c| !c.is_whitespace());
        let got:Vec<TokenType>  = lexer.tokenize(&s).unwrap().into_iter().map(|t|t.kind).collect();
        assert_eq!(got,(vec![TokenType::StringLiteral("abc{dfg}xd{}dx<".into())]));
    }

    #[test]
    fn special_chars_dont_break_string_literals_space(){
        let mut lexer = Lexer::new();
        let got:Vec<TokenType>  = lexer.tokenize("\"abc { dfg } xd {} dx <\"").unwrap().into_iter().map(|t|t.kind).collect();
        assert_eq!(got,(vec![TokenType::StringLiteral("abc { dfg } xd {} dx <".into())]));
    }
    gen_position_tests!(
        single_line_simple,
        "abc def",
        vec![
            Position { row: 1.into(), col: 1.into() },
            Position { row: 1.into(), col: 5.into() },
        ]
    );

    gen_position_tests!(
        multiple_spaces_and_tab,
        "abc\t  def",
        vec![
            Position { row: 1.into(), col: 1.into() },
            Position { row: 1.into(), col: 7.into() },
        ]
    );

    gen_position_tests!(
        linebreak_lf,
        "abc\ndef",
        vec![
            Position { row: 1.into(), col: 1.into() },
            Position { row: 2.into(), col: 1.into() },
        ]
    );

    gen_position_tests!(
        leading_whitespace_newline_tab,
        " \t\n\tabc",
        vec![
            Position { row: 2.into(), col: 2.into() },
        ]
    );

    gen_position_tests!(
        braces_and_colon_across_lines,
        "a:{\n\tb:1\n}",
        vec![
            Position { row: 1.into(), col: 1.into() },
            Position { row: 1.into(), col: 2.into() },
            Position { row: 1.into(), col: 3.into() },
            Position { row: 2.into(), col: 2.into() },
            Position { row: 2.into(), col: 3.into() },
            Position { row: 2.into(), col: 4.into() },
            Position { row: 3.into(), col: 1.into() },
        ]
    );

    #[test]
    fn string_literal_position_after_newline_positions_space(){
        let mut lexer = Lexer::new();
        let got:Vec<Position>  = lexer.tokenize("abc\n\"x y\" z").unwrap().into_iter().map(|t|t.pos).collect();
        assert_eq!(got,(vec![Position {
            row:1.into(),col:1.into()
        },Position {
            row:2.into(),col:1.into()
        },Position {
            row:2.into(),col:7.into()
        },]));
    }

    #[test]
    fn string_literal_position_after_newline_positions_no_space(){
        let mut lexer = Lexer::new();
        let mut s = String::from("abc\n\"x y\" z");
        s.retain(|c| !c.is_whitespace());
        let got:Vec<Position>  = lexer.tokenize(&s).unwrap().into_iter().map(|t|t.pos).collect();
        let expected:Vec<Position> = vec![
            Position { row: 1.into(), col: 1.into() },
            Position { row: 1.into(), col: 4.into() },
            Position { row: 1.into(), col: 8.into() },
        ];
        assert_eq!(got,expected);
    }

    #[test]
    fn unclosed_string_literal_returns_error() {
        let mut lexer = Lexer::new();
        assert!(matches!(
                lexer.tokenize("abc \"unclosed"),
                Err(LexerError::UnclosedStringLiteral(_))
        ));
    }
}
