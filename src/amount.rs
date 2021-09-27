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

// represents the exponent in 10^-10, 10^0, 10^3, etc.  -127..127.
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
    pub count: AmountCounter,
    pub unit: PowerOfTen,
}

/// A NormalizedAmount is just like an Amount except that count is a Big Integer.
/// So sum or difference of any two Amounts sharing the same unit can be represented
/// with a NormalizedAmount.
///
/// For now, have this only for internal use/ops.
#[derive(Debug)]
struct NormalizedAmount {
    count: Integer,
    unit: PowerOfTen,
}

impl Amount {
    pub fn new(count: AmountCounter, unit: PowerOfTen) -> Self {
        // We constrain count to ::counter_max().  If you want to use a bigger value,
        // you must change the unit.
        debug_assert!(count <= Self::counter_max());

        Self { count, unit }
    }

    // note: It's recommended to make this larger than Mint's genesis amount,
    //       else one immediately gets AmountIncompatible errors when reissuing
    //       two outputs: [1, GenesisAmount - 1] and must instead reissue to
    //       larger denoms/units.  not a big deal, but can be confusing when
    //       writing test cases.
    pub fn counter_max() -> AmountCounter {
        // One billion units per tx ought to be enough for anybody! -- danda 2021.
        1000000000
    }

    pub fn unit_max() -> i8 {
        i8::MAX - 9 // this prevents some add/sub edge cases when unit is
                    // near i8::MAX and count is multi-digit.
                    // todo: revisit.
    }

    pub fn unit_min() -> i8 {
        -Self::unit_max()
    }

    fn to_rational(self) -> Rational {
        Rational::from(10).pow(self.unit as i32) * Rational::from(self.count)
    }

    // SI units obtained from:
    //  http://www.knowledgedoor.com/2/units_and_constants_handbook/power_prefixes.html
    //
    // note: presently we special case count == 0.
    //       So it prints 0 instead of eg 0*10^25 or 0*10^2.
    //       This hides the unit information, but is easier
    //       to read.  Anyway, the two cases are equally zero.
    pub fn to_si_string(self) -> String {
        let map: BTreeMap<i8, &str> = [
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
        .collect();

        if self.unit >= -24 && self.unit <= 24 && self.count != 0 {
            let mut unit = self.unit;
            loop {
                if let Some(name) = map.get(&unit) {
                    let diff = self.unit.abs() - unit.abs();
                    let udiff = 10u64.pow(diff as u32);
                    let newcount = self.count as u64 * udiff;
                    let sep = if name.is_empty() { "" } else { " " };
                    return format!("{}{}{}", newcount, sep, name);
                } else {
                    unit += if self.unit >= 0 { -1 } else { 1 };
                }
            }
        }

        // no available SI units, so we just use default string repr.
        self.to_string()
    }

    pub fn max() -> Self {
        Self {
            count: Self::counter_max(),
            unit: Self::unit_max(),
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

    // we may have an Amount like:
    // count = 25000,  unit = 2             (value: 2500000)
    //
    // We want instead an equivalent Amount:
    // count = 25,     unit = 5             (value: 2500000).
    //
    // This function turns the former into the latter.
    fn to_highest_unit(self) -> Self {
        let mut count = self.count;
        let mut unit = self.unit;
        while count % 10 == 0 && unit < Self::unit_max() {
            unit += 1;
            count = count.div_ceil(10);
        }
        Self::new(count, unit)
    }

    // we want to normalize these:
    // count = 25,  unit = 2    = 2500
    // count = 255, unit = 1    = 2550.

    // option a:
    // count = 25, unit = 2    = 25 * 100 = 2500
    // count = 25, unit = 2    = 25 * 10 = 2500    <---- loses information.

    // option b:
    // count = 250,  unit = 1    = 2500  <--- works.  but count can overflow.
    // count = 255,  unit = 1    = 2550.

    // todo: can we somehow normalize without requiring use of BigInteger?
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
            let unit_base = *[a.unit, b.unit].iter().min().unwrap();

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

            (pair.pop().unwrap(), pair.pop().unwrap())
        }
    }

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
            while count_sum > Self::counter_max() || count_sum.clone() % 10 == 0 {
                unit += 1;
                count_sum = count_sum.div_ceil(10);
            }
        }

        match AmountCounter::try_from(count_sum) {
            Ok(v) if v <= Self::counter_max() => Ok(Amount::new(v, unit)),
            _ => Err(Error::AmountIncompatible),
        }
    }

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
            Ok(v) if v <= Self::counter_max() => Ok(Amount::new(v, a.unit)),
            _ => Err(Error::AmountIncompatible),
        }
    }

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
}

impl fmt::Display for Amount {
    // note:  this also creates ::to_string()
    //
    // note: presently we special case count == 0.
    //       So it prints 0 instead of eg 0*10^25 or 0*10^2.
    //       This hides the unit information, but is easier
    //       to read.  Anyway, the two cases are equally zero.
    //
    // note: presently we special case count == 1, so it
    //       prints eg 10^25 instead of 1*10^25.  This is
    //       less regular, but easier to read.  Perhaps it
    //       is better to use the regular form instead.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self.count {
            0 => "0".to_string(),
            1 => format!("10^{}", self.unit),
            _ => format!("{}*10^{}", self.count, self.unit),
        };
        if let Some(width) = f.width() {
            write!(f, "{:width$}", str, width = width)
        } else {
            write!(f, "{}", str)
        }
    }
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

impl PartialEq for Amount {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Amount {}

impl Hash for Amount {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // the following must hold true: k1 == k2 ⇒ hash(k1) == hash(k2)
        // todo: re-implement without to_rational(), which is slow.
        let r = self.to_rational();
        r.hash(state)
    }
}

impl Ord for Amount {
    // We perform the comparison without calculating exponent, which could be
    // very large.  Converting to Rational also works, but is slower.
    // Doubtless this could be optimized much further.
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

impl FromStr for Amount {
    type Err = Error;

    // fixme: implement real parsing for Amount.  for now
    //        we cheat and parse as a u32.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let r = s.parse::<u32>();

        let n = match r {
            Ok(n) => n,
            Err(_) => return Err(Error::AmountUnparseable),
        };

        Ok(Self::new(n, 0))
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
        Self::new(count, unit)
    }
}

impl PartialOrd for Amount {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::Amount;
    use crate::{Error, Result};
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn prop_hash_eq(a: Amount, b: Amount) -> Result<()> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hash;
        use std::hash::Hasher;

        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);

        if a == b {
            assert_eq!(ha.finish(), hb.finish())
        } else {
            assert_ne!(ha.finish(), hb.finish())
        }

        Ok(())
    }

    #[quickcheck]
    fn amount_checked_sub(a: Amount, b: Amount) -> Result<()> {
        let result = a.checked_sub(b);

        match result {
            Ok(diff) => println!("{:?} - {:?} --> {:?}", a, b, diff),
            Err(Error::AmountUnderflow) => assert!(a < b),
            Err(Error::AmountIncompatible) => {
                println!("{:?} - {:?} --> Incompatible", a, b);
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    #[quickcheck]
    fn prop_amount_checked_add(a: Amount, b: Amount) -> Result<()> {
        let result = a.checked_add(b);

        match result {
            Ok(sum) => println!("{:?} - {:?} --> {:?}", a, b, sum),
            Err(Error::AmountIncompatible) => {
                println!("{:?} - {:?} --> Incompatible", a, b);
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

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

    #[quickcheck]
    fn prop_to_si_string(mut amounts: Vec<Amount>) -> Result<()> {
        amounts.sort();

        for a in amounts.into_iter() {
            if a.unit >= 0 && a.unit <= 24 && a.count > 0 {
                println!("{} \t\t<----- {:?}", a.to_si_string(), a);
            }
        }

        Ok(())
    }

    #[test]
    fn to_si_string_vector() -> Result<()> {
        let vector = vec![
            "2*10^-30",
            "2*10^-29",
            "2*10^-28",
            "2*10^-27",
            "2*10^-26",
            "2*10^-25",
            "2 yocto",
            "200 zepto",
            "20 zepto",
            "2 zepto",
            "200 atto",
            "20 atto",
            "2 atto",
            "200 femto",
            "20 femto",
            "2 femto",
            "200 pico",
            "20 pico",
            "2 pico",
            "200 nano",
            "20 nano",
            "2 nano",
            "200 micro",
            "20 micro",
            "2 micro",
            "200 milli",
            "20 milli",
            "2 milli",
            "2 centi",
            "2 deci",
            "2",
            "2 deka",
            "2 hecto",
            "2 kilo",
            "20 kilo",
            "200 kilo",
            "2 mega",
            "20 mega",
            "200 mega",
            "2 giga",
            "20 giga",
            "200 giga",
            "2 tera",
            "20 tera",
            "200 tera",
            "2 peta",
            "20 peta",
            "200 peta",
            "2 exa",
            "20 exa",
            "200 exa",
            "2 zetta",
            "20 zetta",
            "200 zetta",
            "2 yotta",
            "2*10^25",
            "2*10^26",
            "2*10^27",
            "2*10^28",
            "2*10^29",
        ];

        // note: to keep this fn shorter we only test range -30..30, rather than
        // -127..127
        for (idx, i) in (-30..30i8).enumerate() {
            let a = Amount::new(2, i);
            let strval = a.to_si_string();
            // println!("{:?}\t--> {}", a, strval);
            println!("{:<8}\t--> {}", a, strval);
            assert_eq!(strval, vector[idx]);
        }

        // 0 and 1 are special cases.
        assert_eq!(Amount::new(0, -5).to_si_string(), "0");
        assert_eq!(Amount::new(0, 5).to_si_string(), "0");
        assert_eq!(Amount::new(1, 25).to_si_string(), "10^25");
        assert_eq!(Amount::new(1, -25).to_si_string(), "10^-25");
        assert_eq!(Amount::new(1, 0).to_si_string(), "1");
        assert_eq!(Amount::new(1, 1).to_si_string(), "1 deka");
        assert_eq!(Amount::new(1, 2).to_si_string(), "1 hecto");

        Ok(())
    }
}
