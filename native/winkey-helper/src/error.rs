#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    NotFound,
    Exists,
    Unavailable,
    AuthDenied,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "NOT_FOUND",
            Self::Exists => "EXISTS",
            Self::Unavailable => "UNAVAILABLE",
            Self::AuthDenied => "AUTH_DENIED",
        }
    }
}

#[derive(Debug)]
pub struct OpError {
    pub status: i64,
    pub reason: Option<Reason>,
    pub message: &'static str,
}

impl OpError {
    pub fn request(message: &'static str) -> Self {
        Self {
            status: -1,
            reason: None,
            message,
        }
    }
    pub fn native(status: u32, reason: Reason, message: &'static str) -> Self {
        Self {
            status: i64::from(status),
            reason: Some(reason),
            message,
        }
    }
}

pub fn check(status: i32, message: &'static str) -> Result<(), OpError> {
    if status == 0 {
        return Ok(());
    }
    let status = status as u32;
    let reason = match status {
        0x80090016 | 0x80090011 => Reason::NotFound,
        0x8009000f => Reason::Exists,
        0x80090010 | 0x80090022 | 0x80070005 | 0x80090036 => Reason::AuthDenied,
        _ => Reason::Unavailable,
    };
    Err(OpError::native(status, reason, message))
}

pub fn validate_provider_flags(flags: u32) -> Result<(), OpError> {
    if flags & 1 == 0 || flags & 2 != 0 {
        return Err(OpError::native(
            0x80090029,
            Reason::Unavailable,
            "provider is not exclusively hardware backed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_status_preserves_failure_and_neutral_reason() {
        assert!(check(0, "operation").is_ok());
        for (status, reason) in [
            (0x80090016u32, Reason::NotFound),
            (0x80090011, Reason::NotFound),
            (0x8009000f, Reason::Exists),
            (0x80090010, Reason::AuthDenied),
            (0x80090022, Reason::AuthDenied),
            (0x80070005, Reason::AuthDenied),
            (0x80090029, Reason::Unavailable),
            (0x80280001, Reason::Unavailable),
        ] {
            let error = check(status as i32, "operation").unwrap_err();
            assert_eq!(error.reason, Some(reason));
            assert_eq!(error.status, i64::from(status));
        }
    }
    #[test]
    fn only_explicit_hardware_without_software_is_accepted() {
        for flags in [0, 2, 3, 4] {
            assert!(validate_provider_flags(flags).is_err());
        }
        for flags in [1, 5] {
            assert!(validate_provider_flags(flags).is_ok());
        }
    }
}
