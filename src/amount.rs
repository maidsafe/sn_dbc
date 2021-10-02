use crate::{Error, Result};
use rug::ops::DivRounding;
use rug::ops::Pow;
use rug::Integer;
use rug::Rational;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

// represents the exponent in 10^-10, 10^0, 10^3, etc.  -128..127.
pub type PowerOfTen = i8;

// defines size of unsigned counter for an Amount.
pub type AmountCounter = u32;

/// Represents a numeric amount as a count of a power of 10 unit.
/// eg:  1530 could be represented as any of:
///     Amount{count: 153, unit: 1}
///     Amount{count: 1530, unit: 0}
///     Amount{count: 15300, unit: -1}
///     Amount{count: 153000, unit: -2}
///     Amount{count: 1530000, unit: -3}
///     Amount{count: 15300000, unit: -4}
///     Amount{count: 153000000, unit: -5}
///
/// The maximum value of count is 1 billion.  This number is chosen because
/// using USD or Euro as examples, we observe that most real world transactions
/// can be performed for under 1 billion without need to change the unit.
///
/// The general idea is that we can start out with DBC denominations
/// at 10^0, and conduct transactions worth up to 1 billion tokens.
///
/// If one needs to spend more than one 1 billion, then one must
/// use a higher unit, 10^1 at minimum.
///
/// Likewise, if/when the currency gains in real world value, a smaller
/// amount of tokens can buy more.  As such, it can then make sense to
/// specify amounts with a smaller (negative exponent) unit.  This can happen
/// organically, as with the USD dollar where people used to buy eggs with
/// a nickel or dime, but now buy them with dollars.  The market has moved
/// to a higher unit simply because that requires the least number of coins/tokens.
///
/// For a deflationary currency gaining in value such as our DBC's are expected to be,
/// the market movement should normally be towards smaller units rather than larger.
///
/// Any two Amount can be added and subtracted only if they can both be represented
/// in the same unit, without the operation under or overflowing counter.
///
/// In other words, it does not make sense to try and add eg:
///     Amount{count: 15, unit: 0}     (aka 15)  and
///     Amount{count: 1, unit: -20}    (aka 0.00000000000000000001)
///
/// If we normalize both of these to unit: -20, then we have:
///     Amount{count: 1500000000000000000000, unit: -20}     (aka 15)  and
///     Amount{count: 1, unit: -20}    (aka 0.00000000000000000001)
///
/// However 1500000000000000000000 overflows our counter, which only
/// allows values up to 1 billion.  Hence these two amounts are incompatible.
///
/// Since the amounts cannot even add or subtract if they are not close
/// enough together, the Mint will not be able to sum inputs or outputs
/// that are too far apart and will issue an error.
///
/// This prevents users/wallets from generating huge amounts
/// of change with very unlike denominations, eg by subtracting 1 10^-30 from 1 10^3
/// This is a problem when using eg u128 to represent Amounts.  In the worst case with
/// u128 approx 40 outputs can be created when subtracting 1u128 from u128::MAX.
///
/// By comparison, using this Amount scheme with 1 billion max count, the max
/// change outputs is 9.
///
/// Unfortunately when using random number generators for quicktest test cases,
/// the common case becomes near the worst case.  Also, large numbers of inputs and
/// outputs create load on our system, in particular for signing and verifying.
/// Thus we are incentivized to keep the number of change coins as low as we
/// reasonably can.
///
/// In effect, this Amount scheme makes it hard for users to generate essentially
/// worthless dust amounts by accident. It is possible to do if one really tries
/// by reissuing in ever smaller amounts, but wallet software should generally
/// be trying NOT to do that.  And if a user does manage it, then s/he will have
/// difficulty using them in transactions with other people.  Fortunately the
/// reverse process can be used to bring them up into a "normal" range again.
///
#[derive(Clone, Debug, Copy, Default, Serialize, Deserialize)]
pub struct Amount {
    count: AmountCounter,
    unit: PowerOfTen,
}

/// A NormalizedAmount is just like an Amount except that count is a Big Integer.
/// So sum or difference of any two Amounts sharing the same unit can be represented
/// with a NormalizedAmount.
///
/// For now, have this only for internal use/ops.
#[derive(Debug, Default)]
struct NormalizedAmount {
    count: Integer,
    unit: PowerOfTen,
}

impl Amount {
    /// maximum value for Self::count. MUST equal 10^COUNT_MAX_TEN_POW
    //  note: we define these separately to avoid unnecessary runtime 10.pow() call.
    const COUNT_MAX: AmountCounter = 1000000000;

    /// power-of-ten exponent representing COUNT_MAX
    const COUNT_MAX_TEN_POW: PowerOfTen = 9;

    /// creates a new Amount.
    ///   count: count of 10^unit values.
    ///   unit:  power-of-ten exponent, as used in 10^unit
    ///
    /// Returns Error::AmountInvalid if count > Self::counter_max()
    pub fn new(count: AmountCounter, unit: PowerOfTen) -> Result<Self> {
        if count > Self::counter_max() {
            return Err(Error::AmountInvalid);
        }

        Ok(Self { count, unit })
    }

    // only for use in this crate because code in this impl depends on
    // count always being <= Self::counter_max().
    pub(crate) fn new_unchecked(count: AmountCounter, unit: PowerOfTen) -> Self {
        debug_assert!(count <= Self::counter_max());
        Self { count, unit }
    }

    // returns count of 10^unit
    pub fn count(&self) -> AmountCounter {
        self.count
    }

    // returns unit - the power-of-ten exponent, as used in 10^unit
    pub fn unit(&self) -> PowerOfTen {
        self.unit
    }

    /// returns the maximum possible value for count field.
    //
    // note: It's recommended to make this larger than Mint's genesis amount,
    //       else one immediately gets AmountIncompatible errors when reissuing
    //       two outputs: [1, GenesisAmount - 1] and must instead reissue to
    //       larger denoms/units.  not a big deal, but can be confusing when
    //       writing test cases.
    pub fn counter_max() -> AmountCounter {
        // One billion units per tx ought to be enough for anybody! -- danda 2021.
        Self::COUNT_MAX
    }

    /// returns maximum possible value for unit field
    pub fn unit_max() -> PowerOfTen {
        // We decreate max unit by size of counter max so that
        // the largest count of largest Amount unit will always be representable
        // by at most COUNT_MAX_TEN_POW denominations.  In other words, so that
        // it is impossible to create an Amount that cannot be efficiently
        // represented by denominations.
        debug_assert!(10u32.pow(Self::COUNT_MAX_TEN_POW as u32) == Self::COUNT_MAX);
        PowerOfTen::MAX - Self::COUNT_MAX_TEN_POW
    }

    /// returns minimum possible value for unit field
    pub fn unit_min() -> PowerOfTen {
        // We increase max unit by size of counter max so that
        // the largest count of smallest Amount unit will always be representable
        // by at most COUNT_MAX_TEN_POW denominations.  In other words, so that
        // it is impossible to create an Amount that cannot be efficiently
        // represented by denominations.
        debug_assert!(10u32.pow(Self::COUNT_MAX_TEN_POW as u32) == Self::COUNT_MAX);
        PowerOfTen::MIN + Self::COUNT_MAX_TEN_POW
    }

    /// Converts Amount to a rug::Rational number.
    //
    // todo: we should think about if we want to expose rug::Rational
    //       in our public API or not. Possibly this could be exposed
    //       in a companion helper crate.
    pub fn to_rational(self) -> Rational {
        Rational::from(10).pow(self.unit as i32) * Rational::from(self.count)
    }

    /// generates a mapping of PowerOfTen to SI names.
    fn si_map() -> BTreeMap<PowerOfTen, &'static str> {
        [
            (24, "yotta"),
            (21, "zetta"),
            (18, "exa"),
            (15, "peta"),
            (12, "tera"),
            (9, "giga"),
            (6, "mega"),
            (3, "kilo"),
            (2, "hecto"),
            (1, "deka"),
            (0, ""),
            (-1, "deci"),
            (-2, "centi"),
            (-3, "milli"),
            (-6, "micro"),
            (-9, "nano"),
            (-12, "pico"),
            (-15, "femto"),
            (-18, "atto"),
            (-21, "zepto"),
            (-24, "yocto"),
        ]
        .iter()
        .cloned()
        .collect()
    }

    /// generates an SI string for this amount, eg: "253 yotta".
    //
    // SI units obtained from:
    //  http://www.knowledgedoor.com/2/units_and_constants_handbook/power_prefixes.html
    //
    // note: we special case count == 0.
    //       So it prints 0 instead of eg 0*10^25 or 0*10^2.
    //       This hides the unit information, but is easier
    //       to read.  Anyway, the two cases are equally zero.
    pub fn to_si_string(self) -> String {
        let map = Self::si_map();
        // note: this unwrap_or can never fail because map always contains values.
        let min = map.keys().min().unwrap_or(&0);
        let max = map.keys().max().unwrap_or(&0);

        //   25 giga  = 25 * 10^9,   count = 25, unit =  9
        //  250 giga  = 25 * 10^10,  count = 25, unit = 10
        // 2500 giga  = 25 * 10^11,  count = 25, unit = 11

        if self.unit >= *min && self.unit <= *max && self.count != 0 {
            let mut unit = self.unit;
            loop {
                if let Some(name) = map.get(&unit) {
                    let diff = (self.unit.abs() - unit.abs()).abs();
                    let udiff = 10u128.pow(diff as u32);
                    let newcount = self.count as u128 * udiff;

                    // cannot fit in count, so we use to_string() instead.
                    // The alternative is to return the larger number, but then
                    // from_si_string() must be made able to handle it.
                    if newcount > Self::counter_max() as u128 {
                        return self.to_string();
                    }
                    let sep = if name.is_empty() { "" } else { " " };
                    return format!("{}{}{}", newcount, sep, name);
                } else {
                    unit -= 1;
                }
            }
        }

        // no available SI units, so we just use default string repr.
        self.to_string()
    }

    /// generates a notation string, eg: "3*10^-25"
    pub fn to_notation_string(self) -> String {
        format!("{}*10^{}", self.count, self.unit)
    }

    /// returns maximum possible Amount
    pub fn max() -> Self {
        Self {
            count: Self::counter_max(),
            unit: Self::unit_max(),
        }
    }

    /// returns minimum possible Amount
    pub fn min() -> Self {
        Self {
            count: 1,
            unit: Self::unit_min(),
        }
    }

    // creates a normalized Amount from an Amount.
    //
    // todo: perhaps the normalized amount should always be instantiated
    //       with calling ::to_highest_unit() first.  Or maybe all Amount
    //       should be also. might just be extra work when not required though.
    fn to_normalized(self) -> NormalizedAmount {
        NormalizedAmount {
            count: Integer::from(self.count),
            unit: self.unit,
        }
    }

    /// returns an Amount using the highest possible unit
    /// and lowest possible count.
    ///
    /// For example:
    ///   we may have an Amount like:
    ///   count = 25000,  unit = 2             (value: 2500000)
    ///
    ///   We want instead an equivalent Amount:
    ///   count = 25,     unit = 5             (value: 2500000).
    ///
    ///   This function turns the former into the latter.
    pub fn to_highest_unit(self) -> Self {
        let mut count = self.count;
        let mut unit = self.unit;
        while count % 10 == 0 && unit < Self::unit_max() {
            unit += 1;
            count = count.div_ceil(10);
        }

        debug_assert!(count <= Self::counter_max());
        Self { count, unit }
    }

    // we want to normalize these:
    // count = 25,  unit = 2    = 2500
    // count = 255, unit = 1    = 2550.
    //
    // if we normalize to highest unit:
    // count = 25, unit = 2    = 25 * 100 = 2500
    // count = 25, unit = 2    = 25 * 10 = 2500    <---- loses information. can't do this.
    //
    // if we normalize to lowest unit:
    // count = 250,  unit = 1    = 2500  <--- works.  but count can overflow.
    // count = 255,  unit = 1    = 2550.
    //
    // Because count can overflow in one of the Amount, we return
    // NormalizedAmount that uses a big rug::Integer for the count.
    fn normalize(a: Self, b: Self) -> (NormalizedAmount, NormalizedAmount) {
        let a = a.to_highest_unit();
        let b = b.to_highest_unit();

        if a.unit == b.unit {
            (a.to_normalized(), b.to_normalized())
        } else if b.count == 0 {
            (
                a.to_normalized(),
                NormalizedAmount {
                    count: Integer::from(0),
                    unit: a.unit,
                },
            )
        } else if a.count == 0 {
            (
                NormalizedAmount {
                    count: Integer::from(0),
                    unit: b.unit,
                },
                b.to_normalized(),
            )
        } else {
            let unit_distance = if a.unit < b.unit {
                (a.unit..b.unit).len() as u32
            } else {
                (b.unit..a.unit).len() as u32
            };
            // note: this unwrap_or() can never fail because there are two items.
            let unit_base = *[a.unit, b.unit].iter().min().unwrap_or(&0);

            let mut pair: Vec<NormalizedAmount> = [a, b]
                .iter()
                .rev()
                .map(|v| {
                    let count = if v.unit == unit_base {
                        Integer::from(v.count)
                    } else {
                        Integer::from(10).pow(unit_distance) * v.count
                    };
                    NormalizedAmount {
                        count,
                        unit: unit_base,
                    }
                })
                .collect();

            // note: these unwrap_or_default() can never fail because there are two items.
            (
                pair.pop().unwrap_or_default(),
                pair.pop().unwrap_or_default(),
            )
        }
    }

    /// performs addition operation and returns error if operands are incompatible.
    pub fn checked_add(self, other: Self) -> Result<Self> {
        // steps:
        // 1. normalize to same units.  use rug:Integer to represent count.
        // 2. add counts.
        // 3. find unit in which count is less than Self::counter_max()
        // 4. Amount::new()

        let (a, b) = Self::normalize(self, other);

        let mut count_sum = a.count + b.count;
        let mut unit = a.unit;
        if count_sum > 0 {
            let ten = Integer::from(10);
            while count_sum.is_divisible(&ten) {
                // avoid overflowing unit
                if unit == Self::unit_max() {
                    return Err(Error::AmountIncompatible);
                }
                unit += 1;
                count_sum = count_sum.div_exact(&ten);
            }
        }

        match AmountCounter::try_from(count_sum) {
            Ok(v) if v <= Self::counter_max() => Ok(Amount::new(v, unit)?),
            _ => Err(Error::AmountIncompatible),
        }
    }

    /// performs subtraction operation and returns error if operands are incompatible.
    pub fn checked_sub(self, rhs: Self) -> Result<Self> {
        // we do not support negative Amounts
        if self < rhs {
            return Err(Error::AmountUnderflow);
        }

        // steps:
        // 1. normalize to same units.  use rug:Integer to represent count.
        // 2. subtract count.
        // 3. find unit in which count is less than Self::counter_max()
        // 4. Amount::new()
        let (a, b) = Self::normalize(self, rhs);
        let count_diff = a.count - b.count;

        match AmountCounter::try_from(count_diff) {
            Ok(v) if v <= Self::counter_max() => Ok(Amount::new(v, a.unit)?),
            _ => Err(Error::AmountIncompatible),
        }
    }

    /// returns true if operands are compatible for subtraction
    pub fn sub_compatible(self, other: Amount) -> bool {
        self.checked_sub(other).is_ok()
    }

    /// returns true if operands are compatible for addition
    pub fn add_compatible(self, other: Amount) -> bool {
        self.checked_add(other).is_ok()
    }

    /// sums values in iter or returns error if operands are incompatible.
    pub fn checked_sum<I>(iter: I) -> Result<Self>
    where
        I: Iterator<Item = Self>,
    {
        let mut sum = Amount::default();
        for v in iter {
            sum = sum.checked_add(v)?;
        }
        Ok(sum)
    }

    // attempts to parse u128 into Amount
    fn from_str_u128(s: &str) -> Result<Self> {
        match s.parse::<u128>() {
            Ok(v) => Self::try_from(v),
            Err(_) => Err(Error::AmountUnparseable),
        }
    }

    // attempts to parse rug::Rational into Amount
    fn from_str_rational(s: &str) -> Result<Self> {
        match s.parse::<Rational>() {
            Ok(v) => Self::try_from(v),
            Err(_) => Err(Error::AmountUnparseable),
        }
    }

    // attempts to parse a string in the notation: x*10^y
    // where x must be positive and y may be negative.
    fn from_str_notation_full(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(|c| c == '*' || c == '^').collect();

        if parts.len() != 3 {
            return Err(Error::AmountUnparseable);
        }
        if parts[1] != "10" {
            return Err(Error::AmountUnparseable);
        }

        let count: AmountCounter = parts[0].parse().map_err(|_| Error::AmountUnparseable)?;
        let unit: PowerOfTen = parts[2].parse().map_err(|_| Error::AmountUnparseable)?;

        // Self::new will verify that count <= Self::counter_max()
        Self::new(count, unit)
    }

    // attempts to parse a string in the notation: 10^y
    // where y may be negative.
    fn from_str_notation_short(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('^').collect();

        if parts[0] != "10" {
            return Err(Error::AmountUnparseable);
        }
        if parts.len() != 2 {
            return Err(Error::AmountUnparseable);
        }
        let unit: PowerOfTen = parts[1].parse().map_err(|_| Error::AmountUnparseable)?;

        // Self::new will verify that count <= Self::counter_max()
        Self::new(1, unit)
    }

    // attempts to parse an SI string like "253 yotta"
    fn from_str_si(s: &str) -> Result<Self> {
        let map = Self::si_map();

        let parts: Vec<&str> = s.split(' ').collect();
        if parts.len() != 2 {
            return Err(Error::AmountUnparseable);
        }

        let count: AmountCounter = parts[0].parse().map_err(|_| Error::AmountUnparseable)?;
        let name = parts[1].to_lowercase();

        let (unit, _) = map
            .iter()
            .find(|(_, v)| **v == name)
            .ok_or(Error::AmountUnparseable)?;

        Self::new(count, *unit)
    }
}

impl FromStr for Amount {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // note: from_str_u128 is an optimization to avoid calling
        //       presumed slower from_str_rational() if not necessary.
        //       perhaps the optimization is not worth the extra
        //       code/complexity.
        if let Ok(v) = Self::from_str_u128(s) {
            return Ok(v);
        }

        // parses eg 0, 1, 10, 1/10, 1/5, 2/5
        //           15000000000000000000000000000000000000000000000000000000000000000
        if let Ok(v) = Self::from_str_rational(s) {
            return Ok(v);
        }

        // parses eg 3*10^-5
        if let Ok(v) = Self::from_str_notation_full(s) {
            return Ok(v);
        }

        // parses eg 10^-5
        if let Ok(v) = Self::from_str_notation_short(s) {
            return Ok(v);
        }

        // parses eg 253 yotta
        if let Ok(v) = Self::from_str_si(s) {
            return Ok(v);
        }

        Err(Error::AmountUnparseable)
    }
}

// todo: we should think about if we want to expose rug::Integer
//       in our public API or not.  Possibly this could live in
//       a companion helper crate.
impl TryFrom<Integer> for Amount {
    type Error = Error;

    fn try_from(n: Integer) -> Result<Self, Self::Error> {
        let (unit, count) = calc_exponent_bigint(n).ok_or(Error::AmountUnparseable)?;

        let count = AmountCounter::try_from(count).map_err(|_| Error::AmountUnparseable)?;
        Amount::new(count, unit)
    }
}

// todo: we should think about if we want to expose rug::Rational
//       in our public API or not.  Possibly this could live in
//       a companion helper crate.
impl TryFrom<Rational> for Amount {
    type Error = Error;

    fn try_from(n: Rational) -> Result<Self, Self::Error> {
        let mut d = n.denom().clone();
        let mut numer = n.numer().clone();

        match d.cmp(&Integer::from(1)) {
            Ordering::Greater => {
                // denominator is > 1, so we have a fraction.
                // we analyze denominator to find a multiplier such that
                // denominator * multiplier is a power of ten.
                match find_denominator_multiplier(&d) {
                    Some(powten) => {
                        // multiply numerator and denominator by multiplier
                        numer *= &powten;
                        d *= &powten;

                        // calc exp for 10^exp == d
                        let (exp, rem) =
                            calc_exponent_bigint(d.clone()).ok_or(Error::AmountUnparseable)?;

                        if rem != 1 {
                            return Err(Error::AmountUnparseable);
                        }

                        // convert numerator into AmountCounter, if it fits.
                        let count =
                            AmountCounter::try_from(numer).map_err(|_| Error::AmountUnparseable)?;

                        // ::new() will check that count <= ::counter_max()
                        Amount::new(count, -exp)
                    }
                    None => Err(Error::AmountUnparseable),
                }
            }
            Ordering::Equal => {
                // numerator is a rug::Integer
                Self::try_from(numer)
            }
            _ => Err(Error::AmountUnparseable),
        }
    }
}

impl TryFrom<u128> for Amount {
    type Error = Error;

    fn try_from(n: u128) -> Result<Self, Self::Error> {
        let (unit, count) = calc_exponent_u128(n).ok_or(Error::AmountUnparseable)?;

        let count = AmountCounter::try_from(count).map_err(|_| Error::AmountUnparseable)?;
        Amount::new(count, unit)
    }
}

impl TryFrom<u64> for Amount {
    type Error = Error;

    fn try_from(n: u64) -> Result<Self, Self::Error> {
        Self::try_from(n as u128)
    }
}

impl TryFrom<u32> for Amount {
    type Error = Error;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        Self::try_from(n as u128)
    }
}

impl TryFrom<u16> for Amount {
    type Error = Error;

    fn try_from(n: u16) -> Result<Self, Self::Error> {
        Self::try_from(n as u128)
    }
}

impl TryFrom<u8> for Amount {
    type Error = Error;

    fn try_from(n: u8) -> Result<Self, Self::Error> {
        Self::try_from(n as u128)
    }
}

impl fmt::Display for Amount {
    // note:  this also creates ::to_string()
    //
    // note: we special case unit == 0, so it
    //       prints eg 5250 instead of 5250*10^0.
    //
    // note: we special case count == 0.
    //       So it prints 0 instead of eg 0*10^25 or 0*10^2.
    //
    // note: we special case count == 1, so it
    //       prints eg 10^25 instead of 1*10^25.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self.unit {
            0 => format!("{}", self.count),
            _ => match self.count {
                0 => "0".to_string(),
                1 => format!("10^{}", self.unit),
                _ => self.to_notation_string(),
            },
        };
        if let Some(width) = f.width() {
            write!(f, "{:width$}", s, width = width)
        } else {
            write!(f, "{}", s)
        }
    }
}

impl PartialEq for Amount {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Amount {}

impl Hash for Amount {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // the following must hold true: k1 == k2 ⇒ hash(k1) == hash(k2)
        let a = self.to_highest_unit();
        a.count.hash(state);
        a.unit.hash(state);
    }
}

impl Ord for Amount {
    // We perform the comparison without calculating exponent, which could be
    // very large.  Converting to Rational also works, but is slower.
    // Doubtless this could be optimized further.
    fn cmp(&self, other: &Self) -> Ordering {
        let use_rational_impl = false;

        // note: converting to rationals is slower than our custom code below.
        if use_rational_impl {
            return self.to_rational().cmp(&other.to_rational());
        }

        match self.count {
            0 if other.count != 0 => return Ordering::Less,
            0 if other.count == 0 => return Ordering::Equal,
            _ if other.count == 0 => return Ordering::Greater,
            _ => {}
        }

        if self.unit == other.unit {
            return self.count.cmp(&other.count);
        }

        // a: Amount { count: 634438561, unit: 7 },
        // b: Amount { count: 486552,    unit: 10 }    <--- b is lesser

        let a_digits = digits(self.count);
        let b_digits = digits(other.count);

        let a_num_digits = self.unit as isize + a_digits.len() as isize;
        let b_num_digits = other.unit as isize + b_digits.len() as isize;

        if a_num_digits == b_num_digits {
            for (ad, bd) in a_digits.iter().zip(b_digits.iter()) {
                if ad > bd {
                    return Ordering::Greater;
                }
                if ad < bd {
                    return Ordering::Less;
                }
            }
            if a_digits.len() > b_digits.len() && a_digits[b_digits.len()..].iter().any(|d| *d > 0)
            {
                return Ordering::Greater;
            }
            if a_digits.len() < b_digits.len() && b_digits[a_digits.len()..].iter().any(|d| *d > 0)
            {
                return Ordering::Less;
            }
            Ordering::Equal
        } else {
            a_num_digits.cmp(&b_num_digits)
        }
    }
}

impl PartialOrd for Amount {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

use quickcheck::{Arbitrary, Gen};

impl Arbitrary for Amount {
    fn arbitrary(g: &mut Gen) -> Self {
        let count = AmountCounter::arbitrary(g) % Amount::counter_max();

        let unit = loop {
            let c = PowerOfTen::arbitrary(g);
            if c >= Amount::unit_min() && c <= Amount::unit_max() {
                break c;
            }
        };
        Self { count, unit }
    }
}

// calculates largest power-of-ten exponent that is less than amt
// and also returns the remainder
//
// todo: we should think about if we want to expose rug::Integer
//       in our public API or not.  Possibly this could live in
//       a companion helper crate.
fn calc_exponent_bigint(mut amt: Integer) -> Option<(PowerOfTen, Integer)> {
    let mut cnt: PowerOfTen = 0;
    let ten = Integer::from(10);
    while amt.mod_u(10) == 0 && amt > 1 {
        // bail if we would overflow cnt
        if cnt == PowerOfTen::MAX {
            return None;
        }
        // already verified amount is divisible by ten
        amt = amt.div_exact(&ten);
        cnt += 1;
    }
    // count, remainder
    Some((cnt, amt))
}

// calculates largest power-of-ten exponent that is less than amt
// and also returns the remainder
fn calc_exponent_u128(mut amt: u128) -> Option<(PowerOfTen, u128)> {
    let mut cnt: PowerOfTen = 0;

    while amt % 10 == 0 && amt > 1 {
        // bail if we would overflow cnt
        if cnt == PowerOfTen::MAX {
            return None;
        }
        // already verified amount is divisible by ten
        amt /= 10;
        cnt += 1;
    }
    // count, remainder
    Some((cnt, amt))
}

// for a given number 234523 returns vec![2,3,4,5,2,3]
// todo: use an iterative impl instead of recursion.
pub(crate) fn digits(n: AmountCounter) -> Vec<u8> {
    fn x_inner(n: AmountCounter, xs: &mut Vec<u8>) {
        if n >= 10 {
            x_inner(n / 10, xs);
        }
        xs.push((n % 10) as u8);
    }
    let mut xs = Vec::new();
    x_inner(n, &mut xs);
    xs
}

// analyzes an input denominator to find a multiplier such that
// denominator * multiplier is a power of ten.
//
// todo: there is probably a better/faster way to impl this.
//
// todo: we should think about if we want to expose rug::Rational
//       in our public API or not.  Possibly this could live in
//       a companion helper crate.
fn find_denominator_multiplier(i: &Integer) -> Option<Integer> {
    // 1. convert integer to string.
    let digits = i.to_string();

    // 2. strip trailing zeros.
    let leadstr = digits.trim_end_matches('0');
    let leadnum: Integer = match leadstr.parse() {
        Ok(n) => n,
        Err(_) => return None,
    };

    // if 1, we are done.
    if leadnum == 1 {
        return Some(Integer::from(1));
    }

    // 3. increase powers of ten until we find pten into which
    //    leadnum divides evenly
    for j in leadstr.chars().count() as PowerOfTen..=Amount::unit_max() {
        let pten = Integer::from(10).pow(j as u32);

        // todo: Can we get rid of this clone somehow?
        if pten.is_divisible(&leadnum) {
            let unit_big = pten.div_exact(&leadnum);
            return Some(unit_big);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::Amount;
    use crate::{Error, Result};
    use quickcheck_macros::quickcheck;
    use std::collections::BTreeMap;
    use std::convert::TryFrom;

    // tests that if a == b then hash(a) == hash(b)
    //        and if a != b then hash(a) != hash(b)
    #[quickcheck]
    fn prop_hash_eq(a: Amount) -> Result<()> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hash;
        use std::hash::Hasher;

        let count = if a.count < Amount::counter_max() / 10 {
            a.count * 10
        } else if a.count % 10 == 0 {
            a.count / 10
        } else {
            a.count
        };
        let unit = if a.unit < Amount::unit_max() {
            a.unit + 1
        } else {
            a.unit
        };
        let b = Amount::new(count, unit)?;

        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);

        if a == b {
            println!(
                "a == b, {} == {}",
                a.to_notation_string(),
                b.to_notation_string()
            );
            assert_eq!(ha.finish(), hb.finish())
        } else {
            println!(
                "a != b, {} == {}",
                a.to_notation_string(),
                b.to_notation_string()
            );
            assert_ne!(ha.finish(), hb.finish())
        }

        Ok(())
    }

    // tests that two amounts that use different bases but
    // are equal hash to the same value.
    #[test]
    fn hash_eq() -> Result<()> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hash;
        use std::hash::Hasher;

        for unit in Amount::unit_min()..Amount::unit_max() {
            let a = Amount::new(50, unit)?;
            let b = Amount::new(5, unit + 1)?;

            let mut ha = DefaultHasher::new();
            let mut hb = DefaultHasher::new();
            a.hash(&mut ha);
            b.hash(&mut hb);

            assert_eq!(ha.finish(), hb.finish());
        }

        Ok(())
    }

    // Subtracts amounts with checked_sub(). If an Incompatible error occurs,
    // verifies that difference between amounts exceeds nearness limit.
    // If an Underflow error occurs, verifies that left < right.
    #[quickcheck]
    fn prop_amount_checked_sub(a: Amount, b: Amount) -> Result<()> {
        let result = a.checked_sub(b);

        match result {
            Ok(diff) => {
                assert!(a.sub_compatible(b));
                println!("{:?} - {:?} --> {:?}", a, b, diff);
            }
            Err(Error::AmountUnderflow) => assert!(a < b),
            Err(Error::AmountIncompatible) => {
                assert!(!a.sub_compatible(b));
                println!("{:?} - {:?} --> Incompatible", a, b);
            }
            Err(_e) => panic!("Unexpected error"),
        }
        Ok(())
    }

    // Adds amounts with checked_add(). If an Incompatible error occurs,
    // verifies that add_compatible() returns false
    #[quickcheck]
    fn prop_amount_checked_add(a: Amount, b: Amount) -> Result<()> {
        let result = a.checked_add(b);

        match result {
            Ok(sum) => {
                assert_eq!(a.to_rational() + b.to_rational(), sum.to_rational());
                assert!(a.add_compatible(b));
                println!("{:?} - {:?} --> {:?}", a, b, sum);
            }
            Err(Error::AmountIncompatible) => {
                assert!(!a.add_compatible(b));
                println!("{:?} - {:?} --> Incompatible", a, b);
            }
            Err(_e) => panic!("Unexpected error"),
        }
        Ok(())
    }

    // Sorts amounts and then verifies that order is lowest
    // to highest, using both Amount and rug::Rational comparison
    // operators.
    #[quickcheck]
    fn amount_sort(mut amounts: Vec<Amount>) -> Result<()> {
        amounts.sort();

        let mut iter = amounts.iter().peekable();
        loop {
            let cur = iter.next();
            let nxt = iter.peek();
            match (cur, nxt) {
                (Some(a), Some(b)) => {
                    println!("a: {:?}, b: {:?}", a, b);
                    assert!(a <= b);
                    assert!(a.to_rational() <= b.to_rational());
                }
                _ => break,
            }
        }

        Ok(())
    }

    // tests that ::to_string() result can be parsed back into Amount
    #[quickcheck]
    fn prop_to_string_then_parse(amounts: Vec<Amount>) -> Result<()> {
        for amt in amounts.into_iter() {
            let new: Amount = amt.to_string().parse()?;
            assert_eq!(amt, new);
            assert_eq!(amt.to_rational(), new.to_rational());
        }
        Ok(())
    }

    // tests that ::to_si_string() result can be parsed back into Amount
    #[quickcheck]
    fn prop_to_si_string_then_parse(amounts: Vec<Amount>) -> Result<()> {
        for amt in amounts.into_iter() {
            println!("{}", amt.to_si_string());
            let new: Amount = amt.to_si_string().parse()?;
            assert_eq!(amt, new);
            assert_eq!(amt.to_rational(), new.to_rational());
        }
        Ok(())
    }

    // tests that ::to_notation_string() result can be parsed back into Amount
    #[quickcheck]
    fn prop_to_notation_string_then_parse(amounts: Vec<Amount>) -> Result<()> {
        for amt in amounts.into_iter() {
            let new: Amount = amt.to_notation_string().parse()?;
            println!("{}", amt.to_notation_string());
            assert_eq!(amt, new);
            assert_eq!(amt.to_rational(), new.to_rational());
        }
        Ok(())
    }

    // tests that ::to_highest_unit() result is equal to original amount
    #[quickcheck]
    fn prop_to_highest_unit(amounts: Vec<Amount>) -> Result<()> {
        for amt in amounts.into_iter() {
            let new = amt.to_highest_unit();
            assert_eq!(amt, new);
            assert_eq!(amt.to_rational(), new.to_rational());
        }
        Ok(())
    }

    // tests that ::to_rational() result can be converted back into Amount
    #[quickcheck]
    fn prop_to_rational_then_from(amounts: Vec<Amount>) -> Result<()> {
        for amt in amounts.into_iter() {
            println!("{:?} --> {}", amt, amt.to_rational());
            let new = Amount::try_from(amt.to_rational())?;
            assert_eq!(amt, new);
            assert_eq!(amt.to_rational(), new.to_rational());
        }
        Ok(())
    }

    // Verifies that Amount comparison operators agree with
    // rug::Rational comparison operators.  So this is testing
    // the Amount::cmp() fn.
    #[allow(clippy::comparison_chain)]
    #[quickcheck]
    fn prop_ord(amounts: Vec<(Amount, Amount)>) -> Result<()> {
        for (a, b) in amounts.iter() {
            if a > b {
                assert!(a.to_rational() > b.to_rational())
            } else if a < b {
                assert!(a.to_rational() < b.to_rational())
            } else {
                assert!(a.to_rational() == b.to_rational())
            }
        }
        Ok(())
    }

    // not really a test.  this just prints SI strings.
    #[quickcheck]
    fn prop_to_si_string(mut amounts: Vec<Amount>) -> Result<()> {
        amounts.sort();

        for a in amounts.into_iter() {
            println!("{} \t\t<----- {:?}", a.to_si_string(), a);
        }

        Ok(())
    }

    // generates test vector for ::to_string()
    fn gen_to_string_vector() -> BTreeMap<Amount, &'static str> {
        [
            // 10^0 values.
            (Amount::new_unchecked(1, 24), "10^24"),
            (Amount::new_unchecked(1, 0), "1"),
            (Amount::new_unchecked(2, 0), "2"),
            (Amount::new_unchecked(5, 0), "5"),
            (Amount::new_unchecked(9, 0), "9"),
            (Amount::new_unchecked(10, 0), "10"),
            (Amount::new_unchecked(500, 0), "500"),
            (Amount::new_unchecked(999999999, 0), "999999999"),
            // other powers, count == 1
            (Amount::new_unchecked(1, 1), "10"),
            (Amount::new_unchecked(1, -1), "10^-1"),
            (Amount::new_unchecked(1, -2), "10^-2"),
            (Amount::new_unchecked(1, -24), "10^-24"),
            // min, max
            (Amount::max(), "1000000000*10^118"),
            (Amount::min(), "10^-119"),
            // counted values
            (Amount::new_unchecked(2, 24), "2*10^24"),
            (Amount::new_unchecked(25, -1), "25*10^-1"),
            (Amount::new_unchecked(222, -2), "222*10^-2"),
            (Amount::new_unchecked(1000, -24), "1000*10^-24"),
            // zero
            (Amount::new_unchecked(0, 3), "0"),
            (Amount::new_unchecked(0, 0), "0"),
        ]
        .iter()
        .cloned()
        .collect()
    }

    // generates test vector for ::from_str()
    fn gen_from_string_vector() -> BTreeMap<Amount, &'static str> {
        let mut m: BTreeMap<Amount, &'static str> = [
            (Amount::new_unchecked(1, 0), "10^0"),
            (Amount::new_unchecked(1, 1), "10^1"),
            (Amount::new_unchecked(1, 2), "10^2"),
            (Amount::new_unchecked(3, 3), "3*10^3"),
            (Amount::new_unchecked(0, 3), "0*10^3"),
            (Amount::new_unchecked(1, -1), "1/10"),
            (Amount::new_unchecked(2, -1), "2/10"),
            (Amount::new_unchecked(3, -1), "3/10"),
            (Amount::new_unchecked(4, -1), "4/10"),
            (Amount::new_unchecked(5, -1), "5/10"),
            (Amount::new_unchecked(6, -1), "6/10"),
            (Amount::new_unchecked(7, -1), "7/10"),
            (Amount::new_unchecked(8, -1), "8/10"),
            (Amount::new_unchecked(9, -1), "9/10"),
            (Amount::new_unchecked(2, -1), "1/5"),
            (Amount::new_unchecked(4, -1), "2/5"),
            (Amount::new_unchecked(6, -1), "3/5"),
            (Amount::new_unchecked(8, -1), "4/5"),
            (Amount::new_unchecked(1, 0), "5/5"),
            (Amount::new_unchecked(5, -1), "1/2"),
            (Amount::new_unchecked(1, -2), "1/100"),
            (Amount::new_unchecked(2, -2), "2/100"),
            (Amount::new_unchecked(2, -2), "1/50"),
        ]
        .iter()
        .cloned()
        .collect();

        let mut v = gen_to_si_vector();
        v.append(&mut m);
        v
    }

    // generates error cases test vector for ::from_str()
    fn gen_from_string_error_vector() -> BTreeMap<&'static str, Error> {
        let mut m: BTreeMap<&'static str, Error> = Default::default();
        m.insert("1*10^5 ", Error::AmountUnparseable);
        m.insert("1*10^128", Error::AmountUnparseable);
        m.insert("1*10^-129", Error::AmountUnparseable);
        m.insert("1 *10^5", Error::AmountUnparseable);
        m.insert("1**10^5", Error::AmountUnparseable);
        m.insert("1*10^^5", Error::AmountUnparseable);
        m.insert("1000000000000000*10^5", Error::AmountUnparseable);
        m.insert("1/10*10^5", Error::AmountUnparseable);
        m.insert("-1", Error::AmountUnparseable);
        m.insert("-1/10", Error::AmountUnparseable);
        m.insert("0.25", Error::AmountUnparseable);
        m.insert(".25", Error::AmountUnparseable);

        // Todo:
        // would be nice if we could parse exact decimal like these.
        // Unfortunately rug::Rational does not support it.
        // We could possibly parse as float, then convert to Rational.
        // But for now, we just verify that parser gives an error.
        // I'm not wanting to introduce floats anywhere.
        m.insert("0.1", Error::AmountUnparseable);
        m.insert("0.2", Error::AmountUnparseable);
        m
    }

    // tests error cases vector for ::from_str()
    #[test]
    fn from_string_error_vector() -> Result<()> {
        let vector = gen_from_string_error_vector();

        for (input, expect) in vector.iter() {
            let result = input.parse::<Amount>();

            let actual = format!("{}", result.unwrap_err());
            let expected = format!("{}", expect);

            println!("{} : {}", actual, expected);

            assert_eq!(actual, expected);
        }
        Ok(())
    }

    // tests vector for ::from_str()
    #[test]
    fn from_string_vector() -> Result<()> {
        let vector = gen_from_string_vector();

        for (expect, input) in vector.iter() {
            let amt: Amount = input.parse()?;
            println!("{} : {}", expect, amt);
            assert_eq!(*expect, amt);
        }
        Ok(())
    }

    // tests vector for ::to_string()
    #[test]
    fn to_string_vector() -> Result<()> {
        let vector = gen_to_string_vector();

        for (amt, expect) in vector.iter() {
            let s = amt.to_string();
            assert_eq!(s, *expect);
        }
        Ok(())
    }

    // generates test vector for ::to_si_string()
    fn gen_to_si_vector() -> BTreeMap<Amount, &'static str> {
        [
            // Basic values.
            (Amount::new_unchecked(1, 24), "1 yotta"),
            (Amount::new_unchecked(1, 21), "1 zetta"),
            (Amount::new_unchecked(1, 18), "1 exa"),
            (Amount::new_unchecked(1, 15), "1 peta"),
            (Amount::new_unchecked(1, 12), "1 tera"),
            (Amount::new_unchecked(1, 9), "1 giga"),
            (Amount::new_unchecked(1, 6), "1 mega"),
            (Amount::new_unchecked(1, 3), "1 kilo"),
            (Amount::new_unchecked(1, 2), "1 hecto"),
            (Amount::new_unchecked(1, 1), "1 deka"),
            (Amount::new_unchecked(1, 0), "1"),
            (Amount::new_unchecked(1, -1), "1 deci"),
            (Amount::new_unchecked(1, -2), "1 centi"),
            (Amount::new_unchecked(1, -3), "1 milli"),
            (Amount::new_unchecked(1, -6), "1 micro"),
            (Amount::new_unchecked(1, -9), "1 nano"),
            (Amount::new_unchecked(1, -12), "1 pico"),
            (Amount::new_unchecked(1, -15), "1 femto"),
            (Amount::new_unchecked(1, -18), "1 atto"),
            (Amount::new_unchecked(1, -21), "1 zepto"),
            (Amount::new_unchecked(1, -24), "1 yocto"),
            // counted values
            (Amount::new_unchecked(10, 24), "10 yotta"),
            (Amount::new_unchecked(100, 24), "100 yotta"),
            (Amount::new_unchecked(348, 24), "348 yotta"),
            (Amount::new_unchecked(10, -12), "10 pico"),
            (Amount::new_unchecked(100, -12), "100 pico"),
            // overflow 10^3 values
            (Amount::new_unchecked(1000, 24), "1000 yotta"),
            (Amount::new_unchecked(1001, 24), "1001 yotta"),
            (Amount::new_unchecked(10000, 3), "10000 kilo"),
            // zero
            (Amount::new_unchecked(0, 3), "0 kilo"),
            (Amount::new_unchecked(0, 0), "0"),
        ]
        .iter()
        .cloned()
        .collect()
    }

    // generates test vector for ::from_si_str()
    fn gen_from_si_vector() -> BTreeMap<Amount, &'static str> {
        let mut m: BTreeMap<Amount, &'static str> = [
            // case insensitive
            (Amount::new_unchecked(1, -21), "1 zEpto"),
            (Amount::new_unchecked(1, -21), "1 ZEPTO"),
            (Amount::new_unchecked(1, -21), "1 zeptO"),
        ]
        .iter()
        .cloned()
        .collect();

        let mut v = gen_to_si_vector();
        v.append(&mut m);
        v
    }

    // generates error cases test vector for ::from_si_str()
    fn gen_from_si_error_vector() -> BTreeMap<&'static str, Error> {
        let mut m: BTreeMap<&'static str, Error> = Default::default();
        m.insert("1 yotto", Error::AmountUnparseable);
        m.insert("-2 yotta", Error::AmountUnparseable);
        m.insert("2/5 yotta", Error::AmountUnparseable);
        m.insert("stuff", Error::AmountUnparseable);
        m.insert("yotta", Error::AmountUnparseable);
        m.insert("5       yotta", Error::AmountUnparseable);
        m.insert(" 5 yotta ", Error::AmountUnparseable);
        m.insert("5 yotta ", Error::AmountUnparseable);
        m.insert(" 5 yotta", Error::AmountUnparseable);
        m.insert("5 \nyotta", Error::AmountUnparseable);
        m.insert("2000000000 yotta", Error::AmountUnparseable);
        m.insert("10000000000000000000000000 yotta", Error::AmountUnparseable);
        m
    }

    // tests vector for ::to_si_string()
    #[test]
    fn to_si_string_vector() -> Result<()> {
        let vector = gen_to_si_vector();

        for (amt, expect) in vector.iter() {
            let s = amt.to_si_string();
            assert_eq!(s, *expect);
        }
        Ok(())
    }

    // tests vector for ::from_si_str()
    #[test]
    fn from_si_string_vector() -> Result<()> {
        let vector = gen_from_si_vector();

        for (expect, input) in vector.iter() {
            let amt: Amount = input.parse()?;
            assert_eq!(*expect, amt);
        }
        Ok(())
    }

    // tests error cases vector for ::from_si_str()
    #[test]
    fn from_si_string_error_vector() -> Result<()> {
        let vector = gen_from_si_error_vector();

        for (input, expect) in vector.iter() {
            let result = input.parse::<Amount>();

            let actual = format!("{}", result.unwrap_err());
            let expected = format!("{}", expect);

            println!("{} : {}", actual, expected);

            assert_eq!(actual, expected);
        }
        Ok(())
    }
}
