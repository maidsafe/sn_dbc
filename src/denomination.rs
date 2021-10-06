use crate::amount::digits;
use crate::{Amount, AmountCounter, Error, PowerOfTen, Result};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Denomination {
    One(PowerOfTen),
    Two(PowerOfTen),
    Three(PowerOfTen),
    Four(PowerOfTen),
    Five(PowerOfTen),
    Six(PowerOfTen),
    Seven(PowerOfTen),
    Eight(PowerOfTen),
    Nine(PowerOfTen),
}

impl Denomination {
    pub fn to_bytes(&self) -> Vec<u8> {
        // fixme, unwrap. we should serialize manually without serde.
        //        to_bytes() should never fail, should not require a Result.
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self> {
        bincode::deserialize(bytes.as_ref()).map_err(|_| Error::DenominationFromBytes)
    }

    pub fn unit(&self) -> PowerOfTen {
        match *self {
            Self::One(p)
            | Self::Two(p)
            | Self::Three(p)
            | Self::Four(p)
            | Self::Five(p)
            | Self::Six(p)
            | Self::Seven(p)
            | Self::Eight(p)
            | Self::Nine(p) => p,
        }
    }

    pub fn count(&self) -> AmountCounter {
        match *self {
            Self::One(_) => 1,
            Self::Two(_) => 2,
            Self::Three(_) => 3,
            Self::Four(_) => 4,
            Self::Five(_) => 5,
            Self::Six(_) => 6,
            Self::Seven(_) => 7,
            Self::Eight(_) => 8,
            Self::Nine(_) => 9,
        }
    }

    pub fn amount(&self) -> Amount {
        // note: we use new_unchecked because we know the count is less
        // than Amount::counter_max() and we don't wish to return a Result.
        #[rustfmt::skip]
        let amt = match *self {
            Self::One(p)   => Amount::new_unchecked(1, p),
            Self::Two(p)   => Amount::new_unchecked(2, p),
            Self::Three(p) => Amount::new_unchecked(3, p),
            Self::Four(p)  => Amount::new_unchecked(4, p),
            Self::Five(p)  => Amount::new_unchecked(5, p),
            Self::Six(p)   => Amount::new_unchecked(6, p),
            Self::Seven(p) => Amount::new_unchecked(7, p),
            Self::Eight(p) => Amount::new_unchecked(8, p),
            Self::Nine(p)  => Amount::new_unchecked(9, p),
        };
        amt
    }

    pub fn increment(&self) -> Option<Self> {
        match *self {
            Self::One(p) => Some(Self::Two(p)),
            Self::Two(p) => Some(Self::Three(p)),
            Self::Three(p) => Some(Self::Four(p)),
            Self::Four(p) => Some(Self::Five(p)),
            Self::Five(p) => Some(Self::Six(p)),
            Self::Six(p) => Some(Self::Seven(p)),
            Self::Seven(p) => Some(Self::Eight(p)),
            Self::Eight(p) => Some(Self::Nine(p)),
            Self::Nine(p) => {
                if p < Amount::unit_max() {
                    Some(Self::One(p + 1))
                } else {
                    None
                }
            }
        }
    }

    pub fn all() -> Vec<Self> {
        let mut all: Vec<Self> = Default::default();

        for i in PowerOfTen::MIN..=PowerOfTen::MAX {
            let mut v = vec![
                Self::One(i),
                Self::Two(i),
                Self::Three(i),
                Self::Four(i),
                Self::Five(i),
                Self::Six(i),
                Self::Seven(i),
                Self::Eight(i),
                Self::Nine(i),
            ];
            if i < 0 {
                v.reverse();
            }
            all.extend(v);
        }
        all
    }

    // input amount we need to make change for: [count: 1555, unit = 1]    total = 15550

    // change should be:
    //  [count: 1, unit: 4],
    //  [count: 5, unit: 3],
    //  [count: 5, unit: 2],
    //  [count: 5, unit: 1],

    // steps:
    // chosen = []
    // len = input.digits.len()
    // for (idx, digit) in input.digits().enumerate():
    //     if digit == 0, continue
    //     chosen.push([count: digit, unit: len-1-idx + target.unit])

    // output:
    // len = 4
    // [count: 1, unit: 4]
    // [count: 5, unit: 3]
    // [count: 5, unit: 2]
    // [count: 5, unit: 1]

    pub fn make_change(target_amount: Amount) -> Vec<Self> {
        let denoms = Self::all();
        let target = target_amount;

        // note: Amount is carefully sized such that the largest count of
        //       largest unit can be represented by our largest
        //       denomination(s).  As such, make_change never fails
        //       and does not need to return a Result.

        // This is the greedy coin algo.
        // We start with an amount like count: 543021, unit: 7
        // We get the length of digits 543021 == 6
        // We iterate over digits: 5,4,3,0,2,1
        // We make denoms, largest to smallest:
        //  5 --> 5*10^(6-1-0+7) --> 5*10^12
        //  4 --> 4*10^(6-1-1+7) --> 4*10^11
        //  3 --> 3*10^(6-1-2+7) --> 3*10^10
        //  0 --> skip
        //  2 --> 2*10^(6-1-4+7) --> 2*10^8
        //  1 --> 2*10^(6-1-5+7) --> 1*10^7

        let mut chosen = vec![];

        let digits = digits(target.count());
        let len = digits.len() as PowerOfTen;
        let exp_base = len - 1 + target.unit();
        for (idx, digit) in digits.iter().enumerate() {
            if *digit == 0 {
                continue;
            }
            // note: we use new_unchecked because we know the count is less
            // than Amount::counter_max() and we don't wish to return a Result.

            let unit = exp_base - idx as PowerOfTen;
            let amt = Amount::new_unchecked(*digit as AmountCounter, unit);

            // Note: we leave this unwrap() here purposefully.  If it were to
            // ever fail, something is *SERIOUSLY* wrong with the implementation
            // and must be fixed.
            let denom = denoms.iter().find(|d| d.amount() == amt).unwrap();
            chosen.push(*denom);
        }
        chosen
    }

    // Returns the smallest denomination that is larger than the given Amount
    pub fn least_upper_bound(amount: Amount) -> Option<Self> {
        if let Some(largest_denom) = Self::make_change(amount).into_iter().max() {
            for lub in std::iter::successors(Some(largest_denom), Self::increment) {
                if lub.amount() > amount {
                    return Some(lub);
                }
            }
            None
        } else {
            Some(Self::One(Amount::unit_min()))
        }
    }
}

impl TryFrom<Amount> for Denomination {
    type Error = Error;

    fn try_from(amt: Amount) -> Result<Self> {
        let a = amt.to_highest_unit();
        let exp = a.unit();

        let denom = match a.count() {
            1 => Self::One(exp),
            2 => Self::Two(exp),
            3 => Self::Three(exp),
            4 => Self::Four(exp),
            5 => Self::Five(exp),
            6 => Self::Six(exp),
            7 => Self::Seven(exp),
            8 => Self::Eight(exp),
            9 => Self::Nine(exp),
            _ => return Err(Error::DenominationUnknown),
        };
        Ok(denom)
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.amount().fmt(f)
    }
}

impl FromStr for Denomination {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let amt = Amount::from_str(s)?;
        Self::try_from(amt)
    }
}

#[cfg(test)]
mod tests {
    use quickcheck_macros::quickcheck;
    use sn_dbc::{Amount, Denomination, Result};

    #[quickcheck]
    fn prop_make_change(amounts: Vec<Amount>) -> Result<()> {
        if amounts.is_empty() {
            return Ok(());
        }

        let mut max_coins = 0usize;
        let mut max_coins_amt: Amount = Default::default();
        let mut min_coins = usize::MAX;
        let mut min_coins_amt: Amount = Amount::max();
        let mut total_coins = 0usize;
        let mut amt_count = 0usize;
        for amt in amounts.into_iter() {
            let coins = Denomination::make_change(amt);
            println!(
                "amount: {:?}, coins len: {}, coins: {:?}",
                amt,
                coins.len(),
                coins
            );
            let sum = Amount::checked_sum(coins.iter().map(|c| c.amount()))?;
            debug_assert_eq!(sum, amt);
            if coins.len() > max_coins {
                max_coins = coins.len();
                max_coins_amt = amt;
            }
            if !coins.is_empty() && coins.len() < min_coins {
                min_coins = coins.len();
                min_coins_amt = amt;
            }
            if amt != Amount::default() {
                total_coins += coins.len();
                amt_count += 1;
            }
        }

        let avg_coins = total_coins as f32 / amt_count as f32;
        println!("min coins: {}, for amount: {:?}", min_coins, min_coins_amt);
        println!("max coins: {}, for amount: {:?}", max_coins, max_coins_amt);
        println!(
            "avg coins: {}.  ({} total coins for {} inputs)",
            avg_coins, total_coins, amt_count
        );
        println!("---");

        Ok(())
    }
}

impl PartialOrd for Denomination {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Denomination {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.unit() == other.unit() {
            self.count().cmp(&other.count())
        } else {
            self.unit().cmp(&other.unit())
        }
    }
}
