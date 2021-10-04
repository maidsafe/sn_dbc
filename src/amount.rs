use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::cmp;
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

/// Represents a numeric amount as a count (multiple) of 10^unit
/// where amount is unsigned and unit represents a signed exponent.
///
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
/// This prevents users/wallets from generating huge amounts of change with very
/// unlike denominations, eg by subtracting 1 10^-30 from 1 10^3.
/// This is a problem when using eg u128 to represent Amounts.  In the worst
/// case with u128 approx 40 outputs can be created when subtracting 1u128 from
/// u128::MAX.
///
/// By comparison, using this Amount scheme with 1 billion max count, the max
/// change outputs is 9.
///
/// Unfortunately when using random number generators for quicktest test cases,
/// the common case becomes near the worst case.  Also, large numbers of inputs
/// and outputs create load on our system, in particular for signing and
/// verifying. Thus we are incentivized to keep the number of change coins as
/// low as we reasonably can.
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

/// A NormalizedAmount is just like an Amount except that count is a u128
/// So sum or difference of any two compatible Amounts sharing the same unit can
/// be represented with a NormalizedAmount.
///
/// For now, have this only for internal use/ops.
#[derive(Debug, Default)]
struct NormalizedAmount {
    count: u128,
    unit: PowerOfTen,
}

impl Amount {
    /// power-of-ten exponent representing COUNT_MAX
    /// max value for Self::count is 10^9
    //  nine digits per tx ought to be enough for anybody! -- danda 2021.
    const COUNT_MAX_TEN_POW: PowerOfTen = 9;

    /// creates a new Amount.
    ///   count: count of 10^unit values.
    ///   unit:  power-of-ten exponent, as used in 10^unit
    ///
    /// Returns Error::AmountInvalid if count > Self::counter_max()
    #[inline]
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
    #[inline]
    pub fn count(&self) -> AmountCounter {
        self.count
    }

    // returns unit - the power-of-ten exponent, as used in 10^unit
    #[inline]
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
    #[inline]
    pub fn counter_max() -> AmountCounter {
        // Clippy thinks we should just use 10_u32,
        // but the cast preserves AmountCounter abstraction
        #[allow(clippy::unnecessary_cast)]
        (10 as AmountCounter).pow(Self::COUNT_MAX_TEN_POW as u32)
    }

    /// returns maximum possible value for unit field
    #[inline]
    pub fn unit_max() -> PowerOfTen {
        // We decreate max unit by size of counter max so that
        // the largest count of largest Amount unit will always be representable
        // by at most COUNT_MAX_TEN_POW denominations.  In other words, so that
        // it is impossible to create an Amount that cannot be efficiently
        // represented by denominations.
        PowerOfTen::MAX - Self::COUNT_MAX_TEN_POW
    }

    /// returns minimum possible value for unit field
    #[inline]
    pub fn unit_min() -> PowerOfTen {
        // We increase min unit by size of counter max so that
        // the largest count of smallest Amount unit will always be representable
        // by at most COUNT_MAX_TEN_POW denominations.  In other words, so that
        // it is impossible to create an Amount that cannot be efficiently
        // represented by denominations.
        PowerOfTen::MIN + Self::COUNT_MAX_TEN_POW
    }

    /// generates a mapping of PowerOfTen to SI names.
    fn si_map() -> BTreeMap<PowerOfTen, &'static str> {
        vec![
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
        .into_iter()
        .collect()
    }

    /// generates an SI string for this amount, eg: "253 yotta".
    //
    // SI units obtained from:
    //  http://www.knowledgedoor.com/2/units_and_constants_handbook/power_prefixes.html
    //
    // note: There is no SI name for 10^0, so those are just formatted
    //       as regular integer values via ::to_string()
    // note: SI names only extend from 10^-24..10^24.  Outside that range
    //       we fallback to formatting with ::to_string()
    pub fn to_si_string(self) -> String {
        let map = Self::si_map();
        // note: this unwrap_or can never fail because map always contains values.
        // note: we use max+2 to account for eg 10 yotta, 100 yotta.
        let min = map.keys().min().unwrap_or(&0);
        let max = map.keys().max().unwrap_or(&0) + 2;

        //   25 giga  = 25 * 10^9,   count = 25, unit =  9
        //  250 giga  = 25 * 10^10,  count = 25, unit = 10
        // 2500 giga  = 25 * 10^11,  count = 25, unit = 11

        if self.unit >= *min && self.unit <= max && self.count != 0 {
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
    #[inline]
    pub fn to_notation_string(self) -> String {
        format!("{}*10^{}", self.count, self.unit)
    }

    /// returns maximum possible Amount
    #[inline]
    pub fn max() -> Self {
        Self {
            count: Self::counter_max(),
            unit: Self::unit_max(),
        }
    }

    /// returns minimum possible Amount
    #[inline]
    pub fn min() -> Self {
        Self {
            count: 1,
            unit: Self::unit_min(),
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
            count /= 10;
        }

        debug_assert!(count <= Self::counter_max());
        Self { count, unit }
    }

    // we want to normalize these:
    // count = 25,  unit = 2   -->  25 * 100 = 2500
    // count = 255, unit = 1   --> 255 *  10 = 2550
    //
    // if we normalize to highest unit:
    // count = 25, unit = 2    -->  25 * 100 = 2500
    // count = 25, unit = 2    -->  25 * 100 = 2500  <---- loses information. can't do this.
    //
    // if we normalize to lowest unit:
    // count = 250,  unit = 1  -->  25 * 100 = 2500  <--- works. but count can overflow.
    // count = 255,  unit = 1  --> 255 *  10 = 2550
    //
    // Because count can overflow in one of the Amount, we return
    // NormalizedAmount that uses a u128 for the count.
    #[inline]
    fn normalize(a: Self, b: Self) -> Result<(NormalizedAmount, NormalizedAmount)> {
        let a = a.to_highest_unit();
        let b = b.to_highest_unit();

        // find lowest unit, and normalize both amounts to it.
        let base = cmp::min_by(a.unit, b.unit, PowerOfTen::cmp);
        Ok((a.mk_normal(base)?, b.mk_normal(base)?))
    }

    // converts an Amount plus target unit to a NormalizedAmount
    //
    // Example:
    //   self:  Amount{count = 25, unit = 2}      (25 * 100 = 2500)
    //   unit:  -1
    //
    // Result:  NormalizedAmount(count = 25000, unit = -1)
    //          (25000 * 10^-1 = 2500)
    //
    // This function will return AmountIncompatible error if the value
    // of count would exceed capacity of a u128
    #[inline]
    fn mk_normal(self, unit: PowerOfTen) -> Result<NormalizedAmount> {
        let distance = (self.unit as i32 - unit as i32).abs() as u32;

        if self.count == 0 {
            return Ok(NormalizedAmount { count: 0, unit });
        }

        let count = if distance == 0 {
            self.count.into()
        } else {
            10_u128
                .checked_pow(distance)
                .ok_or(Error::AmountIncompatible)?
                .checked_mul(self.count.into())
                .ok_or(Error::AmountIncompatible)?
        };
        Ok(NormalizedAmount { count, unit })
    }

    /// performs addition operation and returns error if operands are incompatible.
    pub fn checked_add(self, other: Self) -> Result<Self> {
        // steps:
        // 1. normalize to same units.  use u128 to represent count.
        // 2. add counts.
        // 3. find unit in which count is less than Self::counter_max()
        // 4. Amount::new()

        let (a, b) = Self::normalize(self, other)?;

        let mut count_sum = a
            .count
            .checked_add(b.count)
            .ok_or(Error::AmountIncompatible)?;

        let mut unit = a.unit;
        if count_sum > Self::counter_max() as u128 {
            while count_sum % 10 == 0 {
                // avoid overflowing unit
                if unit == Self::unit_max() {
                    return Err(Error::AmountIncompatible);
                }
                unit += 1;
                count_sum /= 10;
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
        // 1. normalize to same units.  use u128 to represent count.
        // 2. subtract count.
        // 3. verify that count is <= ::counter_max()
        // 4. Amount::new()
        let (a, b) = Self::normalize(self, rhs)?;

        let count_diff = a
            .count
            .checked_sub(b.count)
            .ok_or(Error::AmountIncompatible)?;

        match AmountCounter::try_from(count_diff) {
            Ok(v) if v <= Self::counter_max() => Ok(Amount::new(v, a.unit)?),
            _ => Err(Error::AmountIncompatible),
        }
    }

    /// returns true if operands are compatible for subtraction
    #[inline]
    pub fn sub_compatible(self, other: Amount) -> bool {
        self.checked_sub(other).is_ok()
    }

    /// returns true if operands are compatible for addition
    #[inline]
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
    #[inline]
    fn from_str_u128(s: &str) -> Result<Self> {
        match s.parse::<u128>() {
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
        // parses eg 2345322200000000
        if let Ok(v) = Self::from_str_u128(s) {
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
    // very large.  Doubtless this could be optimized further.
    fn cmp(&self, other: &Self) -> Ordering {
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

#[cfg(test)]
mod tests {
    use super::Amount;
    use crate::{Error, Result};
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    fn amount_to_f64(amount: Amount) -> f64 {
        // note: f64 (double) max is 10^308.
        // This conversion is ok as our max value is 10^127.
        // note: it can lose some precision
        10_f64.powi(amount.unit().into()) * amount.count() as f64
    }

    // tests that if a == b then hash(a) == hash(b)
    //        and if a != b then hash(a) != hash(b)
    #[quickcheck]
    fn prop_hash_eq(a: Amount) -> Result<()> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hash;
        use std::hash::Hasher;

        // mess with the count and unit a bit so that sometimes
        // we will have two equal amounts (but with diff unit)
        // and sometimes will be unequal.
        //
        // if we just accept two random input Amount, they are almost
        // never equal, except when zero.
        //
        // todo: make this random.
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

    // Subtracts amounts with checked_sub().
    // Verifies that ::sub_compatible() agrees with result.
    // If an Underflow error occurs, verifies that left < right.
    #[quickcheck]
    fn prop_amount_checked_sub_no_zeros(a: Amount, b: Amount) -> TestResult {
        // quickcheck/arbitrary generates too many zero amounts, so we filter them out.
        if a.count() == 0 || b.count() == 0 {
            return TestResult::discard();
        }

        let result = a.checked_sub(b);

        match result {
            Ok(diff) => {
                assert!(a.sub_compatible(b));
                println!("{:>17} - {:>17} --> {:>17}", a, b, diff);
                TestResult::passed()
            }
            Err(Error::AmountUnderflow) => {
                assert!(a < b);
                println!("{:>17} - {:>17} --> Underflow", a, b);
                TestResult::passed()
            }
            Err(Error::AmountIncompatible) => {
                assert!(!a.sub_compatible(b));
                println!("{:>17} - {:>17} --> Incompatible", a, b);
                TestResult::discard()
            }
            Err(_e) => panic!("Unexpected error"),
        }
    }

    // Adds amounts with checked_add().
    // verifies that ::add_compatible() agrees with result.
    #[quickcheck]
    fn prop_amount_checked_add_no_zeros(a: Amount, b: Amount) -> TestResult {
        // quickcheck/arbitrary generates too many zero amounts, so we filter them out.
        if a.count() == 0 || b.count() == 0 {
            return TestResult::discard();
        }

        let result = a.checked_add(b);

        match result {
            Ok(sum) => {
                assert!(a.add_compatible(b));
                println!("{:>17} - {:>17} --> {:>17}", a, b, sum);
                TestResult::passed()
            }
            Err(Error::AmountIncompatible) => {
                println!("{:>17} - {:>17} --> Incompatible", a, b);
                return TestResult::discard();
            }
            Err(_e) => panic!("Unexpected error"),
        }
    }

    // generates test vector for ::checked_add()
    fn gen_checked_sub_vector() -> Vec<((Amount, Amount), Amount)> {
        // note: These are sorted low --> high by third column (difference)
        #[rustfmt::skip]
        let v = [
            // A                  - B                   = C
            (("651475011*10^-119",         "1*10^-115"), "651465011*10^-119"),
            (("124124546*10^-103", "850563121*10^-104"), "390682339*10^-104"),
            (("581180198*10^-102",  "97178235*10^-102"), "484001963*10^-102"),
            (("119472035*10^-101", "327940883*10^-102"), "866779467*10^-102"),
            (( "384480126*10^-96",          "1*10^-96"),  "384480125*10^-96"),
            (( "841033543*10^-79",  "543667133*10^-79"),  "297366410*10^-79"),
            (( "105820672*10^-77",          "1*10^-69"),    "5820672*10^-77"),
            (( "790040192*10^-71",          "1*10^-64"),  "780040192*10^-71"),
            ((         "1*10^-57",  "594686611*10^-66"),  "405313389*10^-66"),
            (( "113245384*10^-62",  "168531878*10^-63"),  "963921962*10^-63"),
            ((         "1*10^-49",          "1*10^-53"),       "9999*10^-53"),
            (( "825918110*10^-52",  "542469245*10^-52"),  "283448865*10^-52"),
            (( "499543991*10^-24",          "1*10^-19"),  "499443991*10^-24"),
            (( "426549552*10^-23",  "248879390*10^-24"),  "401661613*10^-23"),
            (( "955550153*10^-16",           "1*10^-9"),  "945550153*10^-16"),
            ((   "302188006*10^0",     "85405682*10^0"),    "216782324*10^0"),
            ((   "554779653*10^0",    "199023686*10^0"),    "355755967*10^0"),
            ((   "798161306*10^0",     "40473285*10^0"),    "757688021*10^0"),
            ((   "298859784*10^1",     "17017476*10^1"),    "281842308*10^1"),
            ((   "865560126*10^3",    "407339784*10^3"),    "458220342*10^3"),
            ((   "315326177*10^9",           "1*10^14"),    "315226177*10^9"),
            ((  "108985003*10^13",     "8034075*10^13"),   "100950928*10^13"),
            ((  "386106028*10^14",           "1*10^20"),   "385106028*10^14"),
            ((          "1*10^28",   "853053039*10^19"),   "146946961*10^19"),
            ((  "902455929*10^19",   "680586535*10^19"),   "221869394*10^19"),
            ((          "1*10^30",           "1*10^28"),          "99*10^28"),
            ((  "753051559*10^23",           "1*10^31"),   "653051559*10^23"),
            ((  "994704150*10^39",    "28781295*10^39"),   "965922855*10^39"),
            ((  "899926001*10^43",   "283466451*10^43"),   "616459550*10^43"),
            ((   "77195691*10^44",           "1*10^46"),    "77195591*10^44"),
            ((  "847957552*10^46",   "581743615*10^46"),   "266213937*10^46"),
            ((  "957415774*10^46",   "220587596*10^46"),   "736828178*10^46"),
            ((   "10532920*10^50",   "611614002*10^48"),   "441677998*10^48"),
            ((  "294967295*10^49",           "1*10^53"),   "294957295*10^49"),
            ((          "1*10^62",   "992581964*10^53"),     "7418036*10^53"),
            ((  "563254525*10^57",   "294967295*10^57"),   "268287230*10^57"),
            ((  "797877051*10^80",           "1*10^82"),   "797876951*10^80"),
            ((  "294967295*10^93",           "1*10^94"),   "294967285*10^93"),
            ((  "954861654*10^99",   "416126464*10^99"),   "538735190*10^99"),
            (( "178673192*10^100",          "1*10^100"),  "178673191*10^100"),
            (( "222287542*10^112",  "165295741*10^112"),   "56991801*10^112"),
            (( "424920327*10^114",  "991928370*10^113"),  "325727490*10^114"),
            (( "183059974*10^118",  "393684150*10^117"),  "143691559*10^118"),
            // tricky/edge cases
            (("1000000000*10^118",          "1*10^118"),  "999999999*10^118"),
            ((         "1*10^118",        "100*10^115"),          "9*10^117"),
            ((         "2*10^118",         "10*10^117"),         "10*10^117"),
            ((                "0",                 "0"),                 "0"),
            ((        "1*10^-118",                 "0"),         "1*10^-118"),
            ((         "1*10^118",                 "0"),          "1*10^118"),
            ((   "100000000*10^1",    "999999990*10^0"),           "10*10^0"),
            ((   "100000001*10^1",    "999999990*10^0"),           "20*10^0"),
            ((           "5*10^1",           "5*10^-1"),         "495*10^-1"),
            ((           "5*10^1",            "6*10^0"),           "44*10^0"),
            ((        "2*10^-128",         "1*10^-128"),         "1*10^-128"),
        ]
        .iter()
        .map(|((a, b), c)| {
            (
                (a.parse::<Amount>().unwrap(), b.parse::<Amount>().unwrap()),
                c.parse::<Amount>().unwrap(),
            )
        })
        .collect();
        v
    }

    // tests vector for ::checked_sub()
    #[test]
    fn checked_sub_vector() -> Result<()> {
        let vec = gen_checked_sub_vector();

        for ((a, b), expect) in vec.into_iter() {
            let diff = a.checked_sub(b)?;
            assert_eq!(diff, expect);

            println!(
                "{:>17} + {:>17} --> {:>17},",
                a.to_notation_string(),
                b.to_notation_string(),
                diff.to_notation_string()
            );
        }

        Ok(())
    }

    // generates test vector for ::to_string()
    fn gen_checked_sub_error_vector() -> Vec<((Amount, Amount), Error)> {
        #[rustfmt::skip]
        let v = vec![
            //   A                  - B                 --> C
            (( "494072970*10^-91",    "192760731*10^0"), Error::AmountUnderflow),
            ((  "920940182*10^-6",    "826951931*10^0"), Error::AmountUnderflow),
            (( "117340781*10^-94",    "26479897*10^74"), Error::AmountUnderflow),
            ((          "1*10^66",    "20946173*10^98"), Error::AmountUnderflow),
            (( "523159626*10^-61",  "924123698*10^-42"), Error::AmountUnderflow),
            (("213763769*10^-113",   "440776080*10^32"), Error::AmountUnderflow),
            (( "542714871*10^-53",   "294967295*10^60"), Error::AmountUnderflow),
            (( "770965679*10^-22",   "302356584*10^55"), Error::AmountUnderflow),
            (( "226513277*10^-49",   "678788396*10^-8"), Error::AmountUnderflow),
            (("354334406*10^-109",   "826220143*10^71"), Error::AmountUnderflow),
            ((          "1*10^-4",   "415794090*10^74"), Error::AmountUnderflow),
            ((  "100331464*10^51",   "847293049*10^52"), Error::AmountUnderflow),
            ((  "998408154*10^97",  "973666229*10^107"), Error::AmountUnderflow),
            (( "579734442*10^-97",   "900878761*10^25"), Error::AmountUnderflow),
            (( "432278289*10^-65",   "838134323*10^57"), Error::AmountUnderflow),
            (( "299916732*10^-36", "369167752*10^-113"), Error::AmountIncompatible),
            ((  "825227752*10^94",   "959296681*10^53"), Error::AmountIncompatible),
            (( "509952579*10^107",  "141328710*10^-14"), Error::AmountIncompatible),
            (( "828673183*10^101",    "768573847*10^0"), Error::AmountIncompatible),
            ((  "600999783*10^-6",  "444697781*10^-35"), Error::AmountIncompatible),
            ((   "53568465*10^92",  "548646014*10^-14"), Error::AmountIncompatible),
            ((  "627501920*10^99",   "388396516*10^17"), Error::AmountIncompatible),
            ((   "295589053*10^0", "695066944*10^-113"), Error::AmountIncompatible),
            (( "151251573*10^-63",  "414869522*10^-65"), Error::AmountIncompatible),
            (( "346019301*10^-48", "596110845*10^-112"), Error::AmountIncompatible),
            (( "367034410*10^-19", "152237207*10^-101"), Error::AmountIncompatible),
            ((  "273148774*10^90",   "69799112*10^-90"), Error::AmountIncompatible),
            (( "940727335*10^-84", "714229449*10^-108"), Error::AmountIncompatible),
            (( "294967295*10^-75", "139739274*10^-106"), Error::AmountIncompatible),
            ((          "1*10^-6", "205781738*10^-103"), Error::AmountIncompatible),
        ]
        .into_iter()
        .map(|((a, b), c)| {
            (
                (a.parse::<Amount>().unwrap(), b.parse::<Amount>().unwrap()),
                c,
            )
        })
        .collect();
        v
    }

    // tests error vector for ::checked_sub()
    #[test]
    fn checked_sub_error_vector() -> Result<()> {
        let vector = gen_checked_sub_error_vector();

        for ((a, b), expect) in vector.into_iter() {
            let result = a.checked_sub(b);

            let actual = format!("{}", result.unwrap_err());
            let expected = format!("{}", expect);

            assert_eq!(actual, expected);
            println!("{:>17} - {:>17} --> {}", a, b, actual);
        }
        Ok(())
    }

    // generates test vector for ::checked_add()
    fn gen_checked_add_vector() -> Vec<((Amount, Amount), Amount)> {
        // note: These are sorted low --> high by third column (sum)
        #[rustfmt::skip]
        let v = vec![
            // A                  + B                   = C
            (("938165607*10^-117", "990539793*10^-117"),  "19287054*10^-115"),
            (("173590211*10^-109", "642442040*10^-109"), "816032251*10^-109"),
            (("360755221*10^-106",         "1*10^-102"), "360765221*10^-106"),
            (("945525020*10^-100",  "252541240*10^-99"),  "347093742*10^-99"),
            (( "516169476*10^-95",  "942493040*10^-96"),   "61041878*10^-94"),
            (( "115745991*10^-90",  "563529348*10^-90"),  "679275339*10^-90"),
            (( "265558524*10^-88",  "139828367*10^-88"),  "405386891*10^-88"),
            (( "131054936*10^-84",   "22493479*10^-84"),  "153548415*10^-84"),
            ((         "1*10^-82",  "216188463*10^-84"),  "216188563*10^-84"),
            ((         "1*10^-79",  "782826374*10^-81"),  "782826474*10^-81"),
            (( "423819324*10^-77",   "43335124*10^-76"),  "857170564*10^-77"),
            ((  "85611183*10^-72",  "347880770*10^-74"),  "890899907*10^-73"),
            ((         "1*10^-61",  "524343241*10^-66"),  "524443241*10^-66"),
            (( "680292810*10^-64",          "1*10^-64"),  "680292811*10^-64"),
            ((  "53230187*10^-60",  "139021710*10^-60"),  "192251897*10^-60"),
            ((  "86250552*10^-58",  "538655403*10^-58"),  "624905955*10^-58"),
            ((         "1*10^-50",  "663234066*10^-57"),  "673234066*10^-57"),
            ((  "13531180*10^-55",  "234060802*10^-56"),  "369372602*10^-56"),
            ((  "52593244*10^-45",          "1*10^-39"),   "53593244*10^-45"),
            (( "824380262*10^-42",  "793494620*10^-43"),  "903729724*10^-42"),
            ((   "5235158*10^-41",   "69065906*10^-40"),  "695894218*10^-41"),
            (( "281279041*10^-35",   "48120914*10^-34"),  "762488181*10^-35"),
            (( "192868174*10^-35",  "653592856*10^-35"),   "84646103*10^-34"),
            (( "462540316*10^-33",          "1*10^-28"),  "462640316*10^-33"),
            (( "294967295*10^-31",  "400653445*10^-31"),   "69562074*10^-30"),
            (( "192984279*10^-20",  "276162893*10^-20"),  "469147172*10^-20"),
            ((  "25866909*10^-14",  "714902465*10^-15"),  "973571555*10^-15"),
            (( "569186002*10^-13",  "282465874*10^-13"),  "851651876*10^-13"),
            ((  "247352205*10^-1",     "52239257*10^0"),   "769744775*10^-1"),
            ((   "107019934*10^0",     "22828630*10^0"),    "129848564*10^0"),
            ((    "24350153*10^1",     "57906096*10^0"),    "301407626*10^0"),
            ((   "71003420*10^-1",    "312585042*10^0"),    "319685384*10^0"),
            ((    "22673845*10^0",    "298808629*10^0"),    "321482474*10^0"),
            ((   "340152542*10^0",      "2013998*10^0"),     "34216654*10^1"),
            ((   "691533898*10^0",            "1*10^0"),    "691533899*10^0"),
            ((   "350484762*10^0",    "801247478*10^0"),    "115173224*10^1"),
            ((  "389718541*10^10",   "350087368*10^10"),   "739805909*10^10"),
            ((          "1*10^20",   "661988544*10^18"),   "661988644*10^18"),
            ((   "27013950*10^17",   "847790491*10^18"),   "850491886*10^18"),
            ((    "4235611*10^29",   "450670616*10^27"),   "874231716*10^27"),
            ((  "381468754*10^34",   "117762019*10^34"),   "499230773*10^34"),
            ((          "1*10^43",   "513266233*10^36"),   "523266233*10^36"),
            ((          "1*10^44",   "294967295*10^41"),   "294968295*10^41"),
            ((  "189296927*10^44",    "18151593*10^44"),    "20744852*10^45"),
            ((  "137442082*10^47",           "1*10^47"),   "137442083*10^47"),
            ((          "1*10^54",   "752568998*10^47"),   "762568998*10^47"),
            ((  "399993680*10^50",      "603549*10^50"),   "400597229*10^50"),
            ((    "7585699*10^55",   "141737806*10^53"),   "900307706*10^53"),
            ((  "419547882*10^54",   "303433078*10^54"),    "72298096*10^55"),
            ((  "176848236*10^58",           "1*10^61"),   "176849236*10^58"),
            ((  "786425213*10^58",   "267744407*10^58"),   "105416962*10^59"),
            ((          "1*10^62",    "80742399*10^60"),    "80742499*10^60"),
            ((          "1*10^70",   "524346560*10^61"),   "152434656*10^62"),
            ((  "441971350*10^69",   "433907359*10^70"),   "478104494*10^70"),
            ((   "25545542*10^72",   "306908811*10^72"),   "332454353*10^72"),
            ((  "753477419*10^72",   "187814622*10^72"),   "941292041*10^72"),
            ((   "53246615*10^75",   "612614723*10^75"),   "665861338*10^75"),
            ((          "1*10^79",   "843142711*10^77"),   "843142811*10^77"),
            ((   "27627723*10^80",   "424205556*10^80"),   "451833279*10^80"),
            ((  "285042670*10^80",   "375296222*10^80"),   "660338892*10^80"),
            ((  "417025259*10^83",   "773774900*10^82"),   "494402749*10^83"),
            ((  "693604442*10^83",    "15701102*10^83"),   "709305544*10^83"),
            ((  "228111367*10^88",   "693317473*10^88"),    "92142884*10^89"),
            ((  "659729761*10^97",          "1*10^101"),   "659739761*10^97"),
            (( "102084121*10^104",  "488031111*10^104"),  "590115232*10^104"),
            (( "551234637*10^105",  "616253840*10^104"),  "612860021*10^105"),
            ((         "1*10^113",  "718164965*10^108"),  "718264965*10^108"),
            // tricky/edge cases
            ((          "1*10^118", "999999999*10^118"), "1000000000*10^118"),
            ((        "100*10^115",         "9*10^117"),          "1*10^118"),
            ((         "10*10^117",        "10*10^117"),          "2*10^118"),
            ((                 "0",                "0"),                 "0"),
            ((        "1*10^-118",                 "0"),         "1*10^-118"),
            ((         "1*10^118",                 "0"),          "1*10^118"),
            ((    "999999990*10^0",           "10*10^0"),   "100000000*10^1"),
            ((    "999999990*10^0",           "20*10^0"),   "100000001*10^1"),
            ((         "495*10^-1",           "5*10^-1"),           "5*10^1"),
            ((         "495*10^-1",           "5*10^-1"),               "50"),
            ((            "5*10^1",           "5*10^-1"),        "505*10^-1"),
        ]
        .iter()
        .map(|((a, b), c)| {
            (
                (a.parse::<Amount>().unwrap(), b.parse::<Amount>().unwrap()),
                c.parse::<Amount>().unwrap(),
            )
        })
        .collect();
        v
    }

    #[test]
    fn checked_add_vector() -> Result<()> {
        let vec = gen_checked_add_vector();
        // vec.sort_by(|a, b| a.1.cmp(&b.1));

        for ((a, b), expect) in vec.into_iter() {
            let sum = a.checked_add(b)?;
            assert_eq!(sum, expect);

            println!(
                "{:>17} + {:>17} --> {:>17},",
                a.to_notation_string(),
                b.to_notation_string(),
                sum.to_notation_string()
            );
        }

        Ok(())
    }

    // generates test vector for ::to_string()
    fn gen_checked_add_error_vector() -> Vec<((Amount, Amount), Error)> {
        #[rustfmt::skip]
        let v = vec![
            // A                  + B                   = C
            (("360704521*10^-107", "452410098*10^-110"), Error::AmountIncompatible),
            ((  "113557174*10^75",   "495126115*10^69"), Error::AmountIncompatible),
            ((  "217991394*10^47",  "992000263*10^-68"), Error::AmountIncompatible),
            (( "915559338*10^-69",  "811702086*10^106"), Error::AmountIncompatible),
            (("941622180*10^-116",  "211638313*10^-75"), Error::AmountIncompatible),
            (( "172684922*10^105",    "483381463*10^5"), Error::AmountIncompatible),
            (( "266288213*10^-57",  "806640837*10^-72"), Error::AmountIncompatible),
            ((   "316203356*10^8",   "673308207*10^49"), Error::AmountIncompatible),
            ((  "501396086*10^80",  "811096306*10^-85"), Error::AmountIncompatible),
            ((   "759603018*10^0",   "181086985*10^-4"), Error::AmountIncompatible),
            (( "514653915*10^-43",   "79876350*10^-36"), Error::AmountIncompatible),
            ((   "712210175*10^0",  "539345477*10^109"), Error::AmountIncompatible),
            (( "291385938*10^-11",   "449763562*10^35"), Error::AmountIncompatible),
            ((  "61234822*10^-23",          "1*10^-71"), Error::AmountIncompatible),
            (("673995615*10^-107",   "585495885*10^34"), Error::AmountIncompatible),
            ((  "35413871*10^-39",  "519773903*10^104"), Error::AmountIncompatible),
            (( "216862042*10^107",   "64012125*10^-59"), Error::AmountIncompatible),
            (( "883447290*10^-69",  "820338543*10^110"), Error::AmountIncompatible),
            ((         "1*10^-81",   "425316421*10^32"), Error::AmountIncompatible),
            (("587414876*10^-116",  "621367814*10^-82"), Error::AmountIncompatible),
            (( "203698426*10^-74",   "526273353*10^68"), Error::AmountIncompatible),
            ((   "239493867*10^7",    "893155458*10^1"), Error::AmountIncompatible),
            ((  "80387444*10^-85",  "294967295*10^-77"), Error::AmountIncompatible),
            (( "339350117*10^-49",   "118709534*10^28"), Error::AmountIncompatible),
            ((  "322587613*10^28",  "156428109*10^-46"), Error::AmountIncompatible),
            (( "474086011*10^-45",  "553914268*10^-17"), Error::AmountIncompatible),
            ((  "762225810*10^-4",   "201440872*10^17"), Error::AmountIncompatible),
            ((  "975280533*10^32",    "762368334*10^9"), Error::AmountIncompatible),
            ((  "354176969*10^91",  "486887185*10^-89"), Error::AmountIncompatible),
            ((  "752985535*10^44",  "572236868*10^106"), Error::AmountIncompatible),
            ((         "2*10^118",  "999999999*10^118"), Error::AmountIncompatible),
            ((    "999999999*10^0",           "2*10^0"), Error::AmountIncompatible),
        ]
        .into_iter()
        .map(|((a, b), c)| {
            (
                (a.parse::<Amount>().unwrap(), b.parse::<Amount>().unwrap()),
                c,
            )
        })
        .collect();
        v
    }

    #[test]
    fn checked_add_error_vector() -> Result<()> {
        let vector = gen_checked_add_error_vector();

        for ((a, b), expect) in vector.into_iter() {
            let result = a.checked_add(b);

            let actual = format!("{}", result.unwrap_err());
            let expected = format!("{}", expect);

            assert_eq!(actual, expected);
            println!("{:>17} - {:>17} --> {}", a, b, actual);
        }
        Ok(())
    }

    // Sorts amounts and then verifies that order is lowest
    // to highest
    #[quickcheck]
    fn prop_amount_sort(mut amounts: Vec<Amount>) -> Result<()> {
        amounts.sort();

        let mut iter = amounts.iter().peekable();
        loop {
            let cur = iter.next();
            let nxt = iter.peek();
            match (cur, nxt) {
                (Some(a), Some(b)) => {
                    println!("a: {:?}, b: {:?}", a, b);
                    assert!(a <= b);
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
        }
        Ok(())
    }

    // tests that ::to_highest_unit() result is equal to original amount
    #[quickcheck]
    fn prop_to_highest_unit(amounts: Vec<Amount>) -> Result<()> {
        for amt in amounts.into_iter() {
            let new = amt.to_highest_unit();
            assert_eq!(amt, new);
        }
        Ok(())
    }

    // Verifies that Amount comparison operators agree with
    // rug::Rational comparison operators.  So this is testing
    // the Amount::cmp() fn.
    #[allow(clippy::comparison_chain)]
    #[quickcheck]
    fn prop_ord(amounts: Vec<(Amount, Amount)>) -> Result<()> {
        for (a, b) in amounts.into_iter() {
            let af = amount_to_f64(a);
            let bf = amount_to_f64(b);

            if a > b {
                assert!(af > bf);
                println!("{} > {},  {} > {}", a, b, af, bf);
            } else if a < b {
                assert!(af < bf);
                println!("{} < {},  {} < {}", a, b, af, bf);
            } else {
                assert!(af == bf);
                println!("{} == {},  {} == {}", a, b, af, bf);
            }
        }
        Ok(())
    }

    // not really a test.  this just prints SI strings.
    #[test]
    fn list_to_si_string() -> Result<()> {
        for i in -24..27 {
            let amt = Amount::new(1, i)?;
            println!("{:<8} -- {:>10}", amt, amt.to_si_string());
        }
        Ok(())
    }

    // generates test vector for ::to_string()
    fn gen_to_string_vector() -> Vec<(Amount, &'static str)> {
        vec![
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
            (Amount::new_unchecked(1, 1), "10^1"),
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
    }

    // generates test vector for ::from_str()
    fn gen_from_string_vector() -> Vec<(Amount, &'static str)> {
        let mut v = gen_to_string_vector();
        v.append(&mut vec![
            (Amount::new_unchecked(1, 0), "10^0"),
            (Amount::new_unchecked(1, 1), "10^1"),
            (Amount::new_unchecked(1, 2), "10^2"),
            (Amount::new_unchecked(3, 3), "3*10^3"),
            (Amount::new_unchecked(0, 3), "0*10^3"),
        ]);
        v
    }

    // generates error cases test vector for ::from_str()
    fn gen_from_string_error_vector() -> Vec<(&'static str, Error)> {
        vec![
            ("1*10^5 ", Error::AmountUnparseable),
            ("1*10^128", Error::AmountUnparseable),
            ("1*10^-129", Error::AmountUnparseable),
            ("1 *10^5", Error::AmountUnparseable),
            ("1**10^5", Error::AmountUnparseable),
            ("1*10^^5", Error::AmountUnparseable),
            ("1000000000000000*10^5", Error::AmountUnparseable),
            ("1/10*10^5", Error::AmountUnparseable),
            ("-1", Error::AmountUnparseable),
            ("1/10", Error::AmountUnparseable),
            ("-1/10", Error::AmountUnparseable),
            ("0.25", Error::AmountUnparseable),
            (".25", Error::AmountUnparseable),
            // Todo:
            // would be nice if we could parse exact decimal like these.
            // But for now, we just verify that parser gives an error.
            // I'm not wanting to introduce floats anywhere.
            ("0.1", Error::AmountUnparseable),
            ("0.2", Error::AmountUnparseable),
        ]
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
    fn gen_to_si_vector() -> Vec<(Amount, &'static str)> {
        vec![
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
            // 10s, 100s
            (Amount::new_unchecked(1, 4), "10 kilo"),
            (Amount::new_unchecked(1, 5), "100 kilo"),
            (Amount::new_unchecked(1, -22), "100 yocto"),
            (Amount::new_unchecked(1, -23), "10 yocto"),
            (Amount::new_unchecked(1, 25), "10 yotta"),
            (Amount::new_unchecked(1, 26), "100 yotta"),
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
            (Amount::new_unchecked(0, 3), "0"),
            (Amount::new_unchecked(0, -118), "0"),
            (Amount::new_unchecked(0, 0), "0"),
        ]
    }

    // generates test vector for ::from_si_str()
    fn gen_from_si_vector() -> Vec<(Amount, &'static str)> {
        let mut v = gen_to_si_vector();
        v.append(&mut vec![
            // case insensitive
            (Amount::new_unchecked(1, -21), "1 zEpto"),
            (Amount::new_unchecked(1, -21), "1 ZEPTO"),
            (Amount::new_unchecked(1, -21), "1 zeptO"),
        ]);
        v
    }

    // generates error cases test vector for ::from_si_str()
    fn gen_from_si_error_vector() -> Vec<(&'static str, Error)> {
        vec![
            ("1 yotto", Error::AmountUnparseable),
            ("-2 yotta", Error::AmountUnparseable),
            ("2/5 yotta", Error::AmountUnparseable),
            ("stuff", Error::AmountUnparseable),
            ("yotta", Error::AmountUnparseable),
            ("5       yotta", Error::AmountUnparseable),
            (" 5 yotta ", Error::AmountUnparseable),
            ("5 yotta ", Error::AmountUnparseable),
            (" 5 yotta", Error::AmountUnparseable),
            ("5 \nyotta", Error::AmountUnparseable),
            ("2000000000 yotta", Error::AmountUnparseable),
            ("10000000000000000000000000 yotta", Error::AmountUnparseable),
        ]
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
