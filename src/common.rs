//! Common utilities and shared functionality for the Tari lightweight wallet
//!
//! This module provides shared constants, utility functions, and type conversions
//! that are used across multiple modules in the library.

/// Format a number with thousands separators (e.g., 1,234,567)
pub fn format_number<T: std::fmt::Display>(val: T) -> String {
    let val_str = val.to_string();
    let is_negative = val_str.starts_with('-');
    let abs_str = if is_negative { &val_str[1..] } else { &val_str };

    // Split on decimal point if present
    let parts: Vec<&str> = abs_str.split('.').collect();
    let integer_part = parts[0];

    // Format the integer part with commas - return "Invalid" on error
    let formatted_integer = match integer_part
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
    {
        Ok(chunks) => chunks.join(","),
        Err(_) => return "Invalid".to_string(),
    };

    // Reconstruct the number
    let mut result = if parts.len() > 1 {
        // Has decimal part - join with decimal point
        format!("{}.{}", formatted_integer, parts[1])
    } else {
        // No decimal part
        formatted_integer
    };

    if is_negative {
        result = format!("-{result}");
    }
    result
}
