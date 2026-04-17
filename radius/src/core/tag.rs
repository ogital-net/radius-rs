pub(crate) const UNUSED_TAG_VALUE: u8 = 0x00;

/// Tag represents a tag of a RADIUS value.
/// see also: <http://www.ietf.org/rfc/rfc2868.html>
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tag {
    pub(crate) value: u8,
}

impl Tag {
    #[must_use]
    pub fn new(value: u8) -> Self {
        Tag { value }
    }

    #[must_use]
    pub fn new_unused() -> Self {
        Tag {
            value: UNUSED_TAG_VALUE,
        }
    }

    #[must_use]
    pub fn get_value(&self) -> u8 {
        self.value
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.value == UNUSED_TAG_VALUE
    }

    #[must_use]
    pub fn is_valid_value(&self) -> bool {
        (1..=0x1f).contains(&self.value)
    }
}

#[cfg(test)]
mod tests {
    use crate::core::tag::Tag;

    #[test]
    fn test_is_zero() {
        let tag = Tag { value: 0 };
        assert!(tag.is_zero());
        let tag = Tag { value: 1 };
        assert!(!tag.is_zero());
    }

    #[test]
    fn test_is_valid_value() {
        let tag = Tag { value: 1 };
        assert!(tag.is_valid_value());
        let tag = Tag { value: 0 };
        assert!(!tag.is_valid_value());
        let tag = Tag { value: 0x20 };
        assert!(!tag.is_valid_value());
    }
}
