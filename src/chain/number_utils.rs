//! Number utilities for precision arithmetic in blockchain operations
//!
//! This module provides utilities for handling asset amounts and calculations
//! with proper precision, avoiding floating point arithmetic issues.

use crate::error::{ChainError, ChainResult};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Div, Mul, Sub};
use std::str::FromStr;

/// Precision arithmetic number for asset amounts
/// 
/// Uses fixed-point arithmetic to avoid floating point precision issues.
/// All amounts are stored as integers with an implicit decimal precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PrecisionNumber {
    /// The raw integer value (amount * 10^precision)
    raw_value: i128,
    /// Number of decimal places
    precision: u8,
}

impl PrecisionNumber {
    /// Maximum supported precision (18 decimal places)
    pub const MAX_PRECISION: u8 = 18;
    
    /// Create a new PrecisionNumber from raw value and precision
    pub fn new(raw_value: i128, precision: u8) -> ChainResult<Self> {
        if precision > Self::MAX_PRECISION {
            return Err(ChainError::ValidationError {
                field: "precision".to_string(),
                reason: format!("Precision {} exceeds maximum {}", precision, Self::MAX_PRECISION),
            });
        }

        Ok(Self {
            raw_value,
            precision,
        })
    }

    /// Create from decimal string (e.g., "123.456")
    pub fn from_string(s: &str, precision: u8) -> ChainResult<Self> {
        if precision > Self::MAX_PRECISION {
            return Err(ChainError::ValidationError {
                field: "precision".to_string(),
                reason: format!("Precision {} exceeds maximum {}", precision, Self::MAX_PRECISION),
            });
        }

        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() > 2 {
            return Err(ChainError::ValidationError {
                field: "number_format".to_string(),
                reason: "Invalid decimal format".to_string(),
            });
        }

        let integer_part = parts[0].parse::<i128>().map_err(|_| ChainError::ValidationError {
            field: "integer_part".to_string(),
            reason: "Invalid integer part".to_string(),
        })?;

        let decimal_part = if parts.len() == 2 {
            let decimal_str = parts[1];
            if decimal_str.len() > precision as usize {
                return Err(ChainError::ValidationError {
                    field: "decimal_part".to_string(),
                    reason: format!("Decimal part has more than {} digits", precision),
                });
            }
            
            // Pad with zeros if needed
            let padded = format!("{:0<width$}", decimal_str, width = precision as usize);
            padded.parse::<i128>().map_err(|_| ChainError::ValidationError {
                field: "decimal_part".to_string(),
                reason: "Invalid decimal part".to_string(),
            })?
        } else {
            0
        };

        let multiplier = 10_i128.pow(precision as u32);
        let raw_value = integer_part * multiplier + if integer_part >= 0 { decimal_part } else { -decimal_part };

        Ok(Self {
            raw_value,
            precision,
        })
    }

    /// Create from integer value
    pub fn from_integer(value: i128, precision: u8) -> ChainResult<Self> {
        if precision > Self::MAX_PRECISION {
            return Err(ChainError::ValidationError {
                field: "precision".to_string(),
                reason: format!("Precision {} exceeds maximum {}", precision, Self::MAX_PRECISION),
            });
        }

        let multiplier = 10_i128.pow(precision as u32);
        let raw_value = value.checked_mul(multiplier).ok_or_else(|| ChainError::ValidationError {
            field: "value".to_string(),
            reason: "Integer overflow".to_string(),
        })?;

        Ok(Self {
            raw_value,
            precision,
        })
    }

    /// Get the raw integer value
    pub fn raw_value(&self) -> i128 {
        self.raw_value
    }

    /// Get the precision
    pub fn precision(&self) -> u8 {
        self.precision
    }

    /// Convert to floating point (for display purposes only)
    pub fn to_f64(&self) -> f64 {
        let divisor = 10_f64.powi(self.precision as i32);
        self.raw_value as f64 / divisor
    }

    /// Get the integer part
    pub fn integer_part(&self) -> i128 {
        let divisor = 10_i128.pow(self.precision as u32);
        self.raw_value / divisor
    }

    /// Get the fractional part as raw value
    pub fn fractional_part(&self) -> i128 {
        let divisor = 10_i128.pow(self.precision as u32);
        self.raw_value % divisor
    }

    /// Check if the number is zero
    pub fn is_zero(&self) -> bool {
        self.raw_value == 0
    }

    /// Check if the number is positive
    pub fn is_positive(&self) -> bool {
        self.raw_value > 0
    }

    /// Check if the number is negative
    pub fn is_negative(&self) -> bool {
        self.raw_value < 0
    }

    /// Get absolute value
    pub fn abs(&self) -> Self {
        Self {
            raw_value: self.raw_value.abs(),
            precision: self.precision,
        }
    }

    /// Negate the number
    pub fn negate(&self) -> Self {
        Self {
            raw_value: -self.raw_value,
            precision: self.precision,
        }
    }

    /// Convert to different precision
    pub fn to_precision(&self, new_precision: u8) -> ChainResult<Self> {
        if new_precision > Self::MAX_PRECISION {
            return Err(ChainError::ValidationError {
                field: "precision".to_string(),
                reason: format!("Precision {} exceeds maximum {}", new_precision, Self::MAX_PRECISION),
            });
        }

        if new_precision == self.precision {
            return Ok(*self);
        }

        let new_raw_value = if new_precision > self.precision {
            // Increase precision - multiply
            let multiplier = 10_i128.pow((new_precision - self.precision) as u32);
            self.raw_value.checked_mul(multiplier).ok_or_else(|| ChainError::ValidationError {
                field: "value".to_string(),
                reason: "Overflow during precision conversion".to_string(),
            })?
        } else {
            // Decrease precision - divide
            let divisor = 10_i128.pow((self.precision - new_precision) as u32);
            self.raw_value / divisor
        };

        Ok(Self {
            raw_value: new_raw_value,
            precision: new_precision,
        })
    }

    /// Add two numbers (must have same precision)
    pub fn add(&self, other: &Self) -> ChainResult<Self> {
        if self.precision != other.precision {
            return Err(ChainError::ValidationError {
                field: "precision".to_string(),
                reason: "Cannot add numbers with different precisions".to_string(),
            });
        }

        let result = self.raw_value.checked_add(other.raw_value).ok_or_else(|| ChainError::ValidationError {
            field: "value".to_string(),
            reason: "Overflow during addition".to_string(),
        })?;

        Ok(Self {
            raw_value: result,
            precision: self.precision,
        })
    }

    /// Subtract two numbers (must have same precision)
    pub fn subtract(&self, other: &Self) -> ChainResult<Self> {
        if self.precision != other.precision {
            return Err(ChainError::ValidationError {
                field: "precision".to_string(),
                reason: "Cannot subtract numbers with different precisions".to_string(),
            });
        }

        let result = self.raw_value.checked_sub(other.raw_value).ok_or_else(|| ChainError::ValidationError {
            field: "value".to_string(),
            reason: "Overflow during subtraction".to_string(),
        })?;

        Ok(Self {
            raw_value: result,
            precision: self.precision,
        })
    }

    /// Multiply two numbers
    pub fn multiply(&self, other: &Self) -> ChainResult<Self> {
        let result_precision = self.precision + other.precision;
        if result_precision > Self::MAX_PRECISION {
            return Err(ChainError::ValidationError {
                field: "precision".to_string(),
                reason: "Result precision would exceed maximum".to_string(),
            });
        }

        let result = self.raw_value.checked_mul(other.raw_value).ok_or_else(|| ChainError::ValidationError {
            field: "value".to_string(),
            reason: "Overflow during multiplication".to_string(),
        })?;

        Ok(Self {
            raw_value: result,
            precision: result_precision,
        })
    }

    /// Divide two numbers
    pub fn divide(&self, other: &Self) -> ChainResult<Self> {
        if other.raw_value == 0 {
            return Err(ChainError::ValidationError {
                field: "divisor".to_string(),
                reason: "Division by zero".to_string(),
            });
        }

        // For division: (a/10^p1) / (b/10^p2) = (a * 10^p2) / (b * 10^p1)
        // Result precision should be at least max(p1, p2) + extra for accuracy
        let result_precision = std::cmp::max(self.precision, other.precision) + 2;
        let result_precision = std::cmp::min(result_precision, Self::MAX_PRECISION);
        
        // Scale dividend by (10^result_precision) to maintain precision in result
        let scale_factor = 10_i128.pow(result_precision as u32);
        let scaled_dividend = self.raw_value.checked_mul(scale_factor).ok_or_else(|| ChainError::ValidationError {
            field: "value".to_string(),
            reason: "Overflow during division scaling".to_string(),
        })?;

        // Scale divisor by its precision to convert to integer
        let divisor_scale = 10_i128.pow(other.precision as u32);
        let scaled_divisor = other.raw_value;

        // Adjust for self precision
        let self_scale = 10_i128.pow(self.precision as u32);
        
        // Final calculation: (scaled_dividend / self_scale) / (scaled_divisor / divisor_scale)
        // = (scaled_dividend * divisor_scale) / (scaled_divisor * self_scale)
        let final_dividend = scaled_dividend.checked_mul(divisor_scale).ok_or_else(|| ChainError::ValidationError {
            field: "value".to_string(),
            reason: "Overflow during division calculation".to_string(),
        })?;
        
        let final_divisor = scaled_divisor.checked_mul(self_scale).ok_or_else(|| ChainError::ValidationError {
            field: "value".to_string(),
            reason: "Overflow during division calculation".to_string(),
        })?;

        let result = final_dividend / final_divisor;

        Ok(Self {
            raw_value: result,
            precision: result_precision,
        })
    }

    /// Multiply by integer
    pub fn multiply_by_int(&self, multiplier: i128) -> ChainResult<Self> {
        let result = self.raw_value.checked_mul(multiplier).ok_or_else(|| ChainError::ValidationError {
            field: "value".to_string(),
            reason: "Overflow during integer multiplication".to_string(),
        })?;

        Ok(Self {
            raw_value: result,
            precision: self.precision,
        })
    }

    /// Divide by integer
    pub fn divide_by_int(&self, divisor: i128) -> ChainResult<Self> {
        if divisor == 0 {
            return Err(ChainError::ValidationError {
                field: "divisor".to_string(),
                reason: "Division by zero".to_string(),
            });
        }

        let result = self.raw_value / divisor;

        Ok(Self {
            raw_value: result,
            precision: self.precision,
        })
    }
}

impl fmt::Display for PrecisionNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let divisor = 10_i128.pow(self.precision as u32);
        let integer_part = self.raw_value / divisor;
        let fractional_part = (self.raw_value % divisor).abs();

        if self.precision == 0 {
            write!(f, "{}", integer_part)
        } else {
            let fractional_str = format!("{:0width$}", fractional_part, width = self.precision as usize);
            // Remove trailing zeros
            let trimmed = fractional_str.trim_end_matches('0');
            if trimmed.is_empty() {
                write!(f, "{}", integer_part)
            } else {
                write!(f, "{}.{}", integer_part, trimmed)
            }
        }
    }
}

impl FromStr for PrecisionNumber {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Default to 8 decimal places for parsing
        Self::from_string(s, 8)
    }
}

/// Number utilities for common operations
pub struct NumberUtils;

impl NumberUtils {
    /// Convert asset amount to PrecisionNumber
    pub fn asset_amount_to_precision(amount: i64, precision: u8) -> ChainResult<PrecisionNumber> {
        PrecisionNumber::new(amount as i128, precision)
    }

    /// Convert PrecisionNumber to asset amount
    pub fn precision_to_asset_amount(number: &PrecisionNumber) -> ChainResult<i64> {
        if number.raw_value() > i64::MAX as i128 || number.raw_value() < i64::MIN as i128 {
            return Err(ChainError::ValidationError {
                field: "amount".to_string(),
                reason: "Amount exceeds i64 range".to_string(),
            });
        }

        Ok(number.raw_value() as i64)
    }

    /// Calculate percentage
    pub fn calculate_percentage(amount: &PrecisionNumber, percentage: &PrecisionNumber) -> ChainResult<PrecisionNumber> {
        let hundred = PrecisionNumber::from_integer(100, percentage.precision())?;
        let result = amount.multiply(percentage)?;
        result.divide(&hundred)
    }

    /// Calculate compound interest
    pub fn compound_interest(
        principal: &PrecisionNumber,
        rate: &PrecisionNumber,
        periods: u32,
    ) -> ChainResult<PrecisionNumber> {
        let one = PrecisionNumber::from_integer(1, rate.precision())?;
        let rate_plus_one = one.add(rate)?;
        
        let mut result = rate_plus_one;
        for _ in 1..periods {
            result = result.multiply(&rate_plus_one)?;
        }
        
        principal.multiply(&result)
    }

    /// Round to specified decimal places
    pub fn round_to_precision(number: &PrecisionNumber, target_precision: u8) -> ChainResult<PrecisionNumber> {
        if target_precision >= number.precision() {
            return number.to_precision(target_precision);
        }

        let scale_diff = number.precision() - target_precision;
        let divisor = 10_i128.pow(scale_diff as u32);
        let half_divisor = divisor / 2;

        let adjusted_value = if number.raw_value() >= 0 {
            (number.raw_value() + half_divisor) / divisor
        } else {
            (number.raw_value() - half_divisor) / divisor
        };

        PrecisionNumber::new(adjusted_value, target_precision)
    }

    /// Calculate square root using Newton's method
    pub fn sqrt(number: &PrecisionNumber) -> ChainResult<PrecisionNumber> {
        if number.is_negative() {
            return Err(ChainError::ValidationError {
                field: "number".to_string(),
                reason: "Cannot calculate square root of negative number".to_string(),
            });
        }

        if number.is_zero() {
            return Ok(*number);
        }

        // Newton's method for square root
        let target_precision = number.precision();
        let two = PrecisionNumber::from_integer(2, target_precision)?;
        let mut x = *number;
        let mut prev_x = PrecisionNumber::from_integer(0, target_precision)?;

        // Iterate until convergence
        for _ in 0..50 {
            // Ensure both x and prev_x have the same precision before subtraction
            let x_adjusted = x.to_precision(target_precision)?;
            let prev_x_adjusted = prev_x.to_precision(target_precision)?;
            
            if x_adjusted.subtract(&prev_x_adjusted)?.abs().raw_value() <= 1 {
                break;
            }
            prev_x = x_adjusted;
            let quotient = number.divide(&x_adjusted)?;
            // Convert quotient to target precision to match x
            let quotient_adjusted = quotient.to_precision(target_precision)?;
            let sum = x_adjusted.add(&quotient_adjusted)?;
            x = sum.divide(&two)?;
            // Ensure x maintains target precision
            x = x.to_precision(target_precision)?;
        }

        Ok(x)
    }

    /// Format asset amount with given precision for display
    pub fn format_asset_amount(amount: i64, precision: u8) -> String {
        let precision_number = PrecisionNumber::new(amount as i128, precision)
            .unwrap_or_else(|_| PrecisionNumber::new(0, precision).unwrap());
        
        // Format with full precision (including trailing zeros)
        let divisor = 10_i128.pow(precision as u32);
        let integer_part = precision_number.raw_value() / divisor;
        let fractional_part = (precision_number.raw_value() % divisor).abs();
        
        if precision == 0 {
            format!("{}", integer_part)
        } else {
            let fractional_str = format!("{:0width$}", fractional_part, width = precision as usize);
            format!("{}.{}", integer_part, fractional_str)
        }
    }

    /// Parse asset amount string with given precision
    pub fn parse_asset_amount(amount_str: &str, precision: u8) -> ChainResult<i64> {
        let precision_number = PrecisionNumber::from_string(amount_str, precision)?;
        Self::precision_to_asset_amount(&precision_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precision_number_creation() {
        let num = PrecisionNumber::new(12345, 3).unwrap();
        assert_eq!(num.raw_value(), 12345);
        assert_eq!(num.precision(), 3);
    }

    #[test]
    fn test_precision_number_from_string() {
        let num = PrecisionNumber::from_string("123.456", 3).unwrap();
        assert_eq!(num.raw_value(), 123456);
        assert_eq!(num.precision(), 3);

        let num2 = PrecisionNumber::from_string("123", 3).unwrap();
        assert_eq!(num2.raw_value(), 123000);
    }

    #[test]
    fn test_precision_number_display() {
        let num = PrecisionNumber::new(123456, 3).unwrap();
        assert_eq!(num.to_string(), "123.456");

        let num2 = PrecisionNumber::new(123000, 3).unwrap();
        assert_eq!(num2.to_string(), "123");
    }

    #[test]
    fn test_precision_number_arithmetic() {
        let num1 = PrecisionNumber::new(123456, 3).unwrap();
        let num2 = PrecisionNumber::new(654321, 3).unwrap();

        let sum = num1.add(&num2).unwrap();
        assert_eq!(sum.raw_value(), 777777);

        let diff = num2.subtract(&num1).unwrap();
        assert_eq!(diff.raw_value(), 530865);
    }

    #[test]
    fn test_precision_conversion() {
        let num = PrecisionNumber::new(123456, 3).unwrap();
        let converted = num.to_precision(5).unwrap();
        assert_eq!(converted.raw_value(), 12345600);
        assert_eq!(converted.precision(), 5);
    }

    #[test]
    fn test_number_utils_percentage() {
        let amount = PrecisionNumber::from_string("100.00", 2).unwrap();
        let percentage = PrecisionNumber::from_string("15.50", 2).unwrap();
        let result = NumberUtils::calculate_percentage(&amount, &percentage).unwrap();
        assert_eq!(result.to_string(), "15.5");
    }

    #[test]
    fn test_number_utils_sqrt() {
        let num = PrecisionNumber::from_string("9.00", 2).unwrap();
        let sqrt_result = NumberUtils::sqrt(&num).unwrap();
        assert!((sqrt_result.to_f64() - 3.0).abs() < 0.01);
    }

    #[test]
    fn test_precision_number_multiply_divide() {
        let num1 = PrecisionNumber::from_string("10.5", 1).unwrap();
        let num2 = PrecisionNumber::from_string("2.0", 1).unwrap();

        let product = num1.multiply(&num2).unwrap();
        assert_eq!(product.precision(), 2);
        assert_eq!(product.to_string(), "21");

        let quotient = num1.divide(&num2).unwrap();
        assert_eq!(quotient.to_string(), "5.25");
    }

    #[test]
    fn test_rounding() {
        let num = PrecisionNumber::from_string("123.456789", 6).unwrap();
        let rounded = NumberUtils::round_to_precision(&num, 2).unwrap();
        assert_eq!(rounded.to_string(), "123.46");
    }
}