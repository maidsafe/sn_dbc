use crate::amount::digits;
use crate::{Amount, AmountCounter, PowerOfTen, Result};
use serde::{Deserialize, Serialize};

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
        bincode::serialize(self).unwrap() // fixme, unwrap
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes).unwrap()) // fixme, unwrap
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
        match *self {
            Self::One(p) => Amount::new(1, p),
            Self::Two(p) => Amount::new(2, p),
            Self::Three(p) => Amount::new(3, p),
            Self::Four(p) => Amount::new(4, p),
            Self::Five(p) => Amount::new(5, p),
            Self::Six(p) => Amount::new(6, p),
            Self::Seven(p) => Amount::new(7, p),
            Self::Eight(p) => Amount::new(8, p),
            Self::Nine(p) => Amount::new(9, p),
        }
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

    fn powname(count: u8, p: PowerOfTen) -> String {
        let abs = p.abs();
        if p < 0 {
            format!("{}tenneg{}", count, abs)
        } else {
            format!("{}tento{}", count, abs)
        }
    }

    // Some examples:
    //   Seven(-50) -> 7tenneg50
    //   One(-5)    -> 1tenneg5
    //   Six(0)     -> 6tento0        (aka six)
    //   Nine(3)    -> 9tento3        (aka nine thousand)
    pub fn to_powname_string(&self) -> String {
        match *self {
            Self::One(p) => Self::powname(1, p),
            Self::Two(p) => Self::powname(2, p),
            Self::Three(p) => Self::powname(3, p),
            Self::Four(p) => Self::powname(4, p),
            Self::Five(p) => Self::powname(5, p),
            Self::Six(p) => Self::powname(6, p),
            Self::Seven(p) => Self::powname(7, p),
            Self::Eight(p) => Self::powname(8, p),
            Self::Nine(p) => Self::powname(9, p),
        }
    }

    pub fn to_integer_string(&self) -> String {
        self.amount().to_string()
    }

    pub fn all() -> Vec<Self> {
        let mut all: Vec<Self> = Default::default();

        for i in -PowerOfTen::MAX..PowerOfTen::MAX {
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

        // This is the greedy coin algo.
        // It is simple, but can fail for certain denom sets and target amounts as
        // it picks more coins than necessary.
        // Eg for denoms: [1, 15, 25] and target amount = 30, it picks
        // [25,1,1,1,1,1] instead of [15,15].
        // To avoid this, the denom set must be chosen carefully.
        // See https://stackoverflow.com/questions/13557979/why-does-the-greedy-coin-change-algorithm-not-work-for-some-coin-sets

        let mut chosen = vec![];

        let digits = digits(target.count);
        let len = digits.len() as i8;
        for (idx, digit) in digits.iter().enumerate() {
            if *digit == 0 {
                continue;
            }
            let amt = Amount::new(*digit as AmountCounter, len - 1 - idx as i8 + target.unit);

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
