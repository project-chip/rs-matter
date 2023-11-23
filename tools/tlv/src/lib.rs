#[derive(Clone, Copy, Debug)]
pub enum InputBase {
    Hex,
    Dec,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParseError {
    pub input: String,
    pub error: std::num::ParseIntError,
}

impl InputBase {
    /// Parses a single input
    ///
    /// # Examples
    ///
    /// ```
    /// use parser::InputBase;
    ///
    /// assert_eq!(InputBase::Hex.try_parse("12"), Ok(0x12));
    /// assert_eq!(InputBase::Dec.try_parse("12"), Ok(12));
    /// assert_eq!(InputBase::Hex.try_parse("0x12"), Ok(0x12));
    /// assert_eq!(InputBase::Dec.try_parse("0x12"), Ok(0x12)); // always hex if prefix
    /// ```
    pub fn try_parse(self, s: impl AsRef<str>) -> Result<u8, ParseError> {
        let s = s.as_ref();

        let error_map = |error: std::num::ParseIntError| ParseError {
            input: s.into(),
            error,
        };

        if s.starts_with("0x") {
            // this is always hex
            return Ok(u8::from_str_radix(&s[2..], 16).map_err(error_map)?);
        }

        Ok(match self {
            InputBase::Hex => u8::from_str_radix(s, 16),
            InputBase::Dec => u8::from_str_radix(s, 10),
        }
        .map_err(error_map)?)
    }

    /// Parses a separated list of values.
    ///
    /// # Examples
    ///
    /// ```
    /// use parser::InputBase;
    ///
    /// assert_eq!(InputBase::Hex.parse_list("1, 2, 10, 20", ','), vec![1, 2, 0x10, 0x20]);
    /// assert_eq!(InputBase::Dec.parse_list("1, 2, 10, 20", ','), vec![1, 2, 10, 20]);
    /// assert_eq!(InputBase::Dec.parse_list("1:2:3:123", ':'), vec![1, 2, 3, 123]);
    ///
    /// // Parsing is lenient (ignores/skips errors)
    /// assert_eq!(InputBase::Dec.parse_list("1, 2, foo, 10, bar, 20", ','), vec![1, 2, 10, 20]);
    /// ```
    pub fn parse_list(self, list: &str, separator: char) -> Vec<u8> {
        // lenient parsing
        let parsed = list
            .split(separator)
            .clone()
            .map(|b| self.try_parse(b.trim()))
            .collect::<Vec<_>>();

        parsed
            .into_iter()
            .filter_map(|r| {
                if let Err(ref err) = r {
                  eprintln!("NOTE: error parsing '{}': {:?}", err.input, err.error);
                }
                r.ok()
            })
            .collect()
    }
}
