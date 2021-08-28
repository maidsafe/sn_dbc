// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// This is a tool to auto-regenerate the denomination.rs source file.
///
/// This tool uses sn_dbc::Amount.  So amount could be defined
/// as u16, u32, u64, u128... and the appropriate enum variants
/// will be used for the size.  This makes it easier to experiment
/// with different sizes, esp u64 and u128.
///
/// Usage:  (from crate root dir)
///     $ cargo run --bin denom-gen > /tmp/d.rs && mv /tmp/d.rs src/denomination.rs
use sn_dbc::Amount;

// uncomment to use this instead.
// type Amount = u64;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let list_mode = args.contains(&"--list".to_string());
    let last_arg_idx = if list_mode { 2 } else { 1 };

    let algo = if args.len() > last_arg_idx {
        args[last_arg_idx].clone()
    } else {
        "default".to_string()
    };
    let generator = DenominationGenerator::by_algo_name(&algo);

    if list_mode {
        generator.print_list();
    } else {
        generator.print_file();
    }
    Ok(())
}

struct DenominationGenerator {
    list: Vec<(String, Amount)>,
}

impl DenominationGenerator {
    fn by_algo_name(name: &str) -> Self {
        match name {
            "powers_of_two" => Self::powers_of_two(),
            "powers_of_ten" => Self::powers_of_ten(),
            "powers_of_ten_1_to_9" => Self::powers_of_ten_1_to_9(),
            "default" => Self::powers_of_ten_1_to_9(),
            _ => panic!("algo name `{}` unknown", name),
        }
    }

    #[allow(clippy::unnecessary_cast)]
    fn powers_of_ten_1_to_9() -> Self {
        let mut list: Vec<(String, Amount)> = Default::default();

        let mut power = 0u32;
        let mut digit = 1;

        let names = [
            "one", "tau", "mil", "bil", "tril", "quad", "quint", "sic", "set", "ott", "non", "det",
            "unt",
        ];
        let digit_names = [
            "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        ];

        loop {
            let amt: Amount = digit as Amount * (10 as Amount).pow(power);
            let name_idx = power as usize / 3;

            let prefix = match power % 3 {
                0 => "",
                1 => "ten",
                2 => "hundred",
                _ => "???",
            };

            let name = format!(
                "{}{}{}",
                Self::ucfirst(digit_names[digit]),
                Self::ucfirst(prefix),
                Self::ucfirst(names[name_idx])
            );
            // println!("\t power: {} \t \t digit: {} \t amt: {} \t idx: {}, name: {}", power, digit, amt, name_idx, name);

            list.push((name, amt));

            if amt > Amount::MAX / 2 {
                break;
            }

            digit += 1;
            if digit == 10 {
                power += 1;
                digit = 1;
            }
        }

        Self { list }
    }

    #[allow(clippy::unnecessary_cast)]
    fn powers_of_ten() -> Self {
        let mut list: Vec<(String, Amount)> = Default::default();

        let mut power = 0u32;

        let names = [
            "one", "tau", "mil", "bil", "tril", "quad", "quint", "sic", "set", "ott", "non", "det",
            "unt",
        ];

        loop {
            let amt: Amount = (10 as Amount).pow(power);
            let name_idx = power as usize / 3;

            let prefix = match power % 3 {
                0 => "",
                1 => "ten",
                2 => "hundred",
                _ => "???",
            };

            let name = format!(
                "{}{}",
                Self::ucfirst(prefix),
                Self::ucfirst(names[name_idx])
            );

            list.push((name, amt));

            if name_idx == names.len() - 1 || amt > Amount::MAX / 2 {
                break;
            }

            power += 1;
        }

        Self { list }
    }

    #[allow(clippy::unnecessary_cast)]
    fn powers_of_two() -> Self {
        let mut list: Vec<(String, Amount)> = Default::default();

        let mut power = 0u32;

        loop {
            let amt: Amount = (2 as Amount).pow(power);

            let name = format!("TwoToPowerOf{}", power);
            list.push((name, amt));

            if amt > Amount::MAX / 2 {
                break;
            }

            power += 1;
        }

        Self { list }
    }
}

impl DenominationGenerator {
    fn ucfirst(s: &str) -> String {
        let mut s2 = s.to_string();
        if let Some(r) = s2.get_mut(0..1) {
            r.make_ascii_uppercase();
        }
        s2
    }

    fn print_file(&self) {
        self.print_file_head();
        self.print_struct();
        self.print_impl();
        self.print_tests();
    }

    fn print_file_head(&self) {
        println!(
            r#"
// Do not modify!
// this file is automatically generated by denom-gen.rs.
// Please make any modifications there and re-generate via:
// cargo run --example denom-gen > tmp.rs && mv tmp.rs src/denomination.rs
use crate::{{Amount, Error, Result}};
use serde::{{Deserialize, Serialize}};
use std::convert::TryFrom;
"#
        );
    }

    fn print_struct(&self) {
        println!(
            r#"
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum Denomination {{
{}
}}
"#,
            self.gen_enum_variants()
        );
    }

    fn print_impl(&self) {
        println!(
            r#"
impl Denomination {{

    pub fn to_be_bytes(self) -> [u8; 2] {{
        (self as u16).to_be_bytes()
    }}

    pub fn from_be_bytes(bytes: [u8; 2]) -> Result<Self> {{
        let variant = u16::from_be_bytes(bytes);
        if variant >= {} {{
            return Err(Error::UnknownDenomination);
        }}
        Ok(unsafe {{ std::mem::transmute(variant) }})
    }}

    pub fn amount(&self) -> Amount {{
        match *self {{
{}
            Self::Genesis => Amount::MAX,
        }}
    }}

    pub fn all() -> Vec<Self> {{
        vec![
{}
            Self::Genesis,
        ]
    }}

    pub fn make_change(target_amount: Amount) -> Vec<Self> {{
        let denoms = Self::all();

        // This is the greedy coin algo.
        // It is simple, but can fail for certain denom sets and target amounts as
        // it picks more coins than necessary.
        // Eg for denoms: [1, 15, 25] and target amount = 30, it picks
        // [25,1,1,1,1,1] instead of [15,15].
        // To avoid this, the denom set must be chosen carefully.
        // See https://stackoverflow.com/questions/13557979/why-does-the-greedy-coin-change-algorithm-not-work-for-some-coin-sets
        let mut remaining = target_amount;
        let mut chosen = vec![];
        for denom in denoms.iter().rev() {{
            let amount = denom.amount();
            let n = remaining / amount;
            if n > 0 {{
                for _i in 0..n {{
                    chosen.push(*denom);
                }}
                remaining %= amount;
                if remaining == 0 {{
                    break;
                }}
            }}
        }}
        chosen
    }}
}}

impl TryFrom<Amount> for Denomination {{
type Error = Error;

    fn try_from(n: Amount) -> Result<Self> {{
        match n {{
{}
            Amount::MAX => Ok(Self::Genesis),
            _ => Err(Error::UnknownDenomination),
        }}
    }}
}}
"#,
            self.num_variants(),
            self.gen_name_to_amount_matches(),
            self.gen_all_variants(),
            self.gen_try_from_matches()
        );
    }

    fn num_variants(&self) -> usize {
        self.list.len() + 1 // + 1 for Genesis variant.
    }

    fn print_tests(&self) {
        println!(
            r#"
#[cfg(test)]
mod tests {{
    use sn_dbc::{{Amount, Denomination, Result}};
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn make_change(amounts: Vec<Amount>) -> Result<()> {{
        if amounts.is_empty() {{
            return Ok(());
        }}

        let mut max_coins = 0usize;
        let mut max_coins_amt: Amount = Default::default();
        let mut min_coins = usize::MAX;
        let mut min_coins_amt: Amount = Amount::MAX;
        let mut total_coins = 0usize;
        for amt in amounts.clone().into_iter() {{
            let coins = Denomination::make_change(amt);
            // println!("amount: {{}}, coins len: {{}}, coins: {{:?}}", amt, coins.len(), coins);
            let sum: Amount = coins.iter().map(|c| c.amount()).sum();
            assert_eq!(sum, amt);
            if coins.len() > max_coins {{
                max_coins = coins.len();
                max_coins_amt = amt;
            }}
            if !coins.is_empty() && coins.len() < min_coins {{
                min_coins = coins.len();
                min_coins_amt = amt;
            }}
            total_coins += coins.len();
        }}
        
        let avg_coins = total_coins / amounts.len();
        println!("min coins: {{}}, for amount: {{}}", min_coins, min_coins_amt);
        println!("max coins: {{}}, for amount: {{}}", max_coins, max_coins_amt);
        println!("avg coins: {{}} across {{}} total coins", avg_coins, total_coins);
        println!("---");

        Ok(())
    }}
}}
"#
        );
    }

    fn gen_enum_variants(&self) -> String {
        let mut s: String = Default::default();
        for (name, _) in self.list.iter() {
            s.push_str(&format!("    {},\n", name));
        }
        s.push_str(&"    Genesis,\n".to_string());
        s
    }

    fn gen_all_variants(&self) -> String {
        let mut s: String = Default::default();
        for (name, _) in self.list.iter() {
            s.push_str(&format!("            Self::{},\n", name));
        }
        s
    }

    fn gen_name_to_amount_matches(&self) -> String {
        let mut s: String = Default::default();
        for (name, amt) in self.list.iter() {
            s.push_str(&format!("            Self::{: <20} => {},\n", name, amt));
        }
        s
    }

    fn gen_try_from_matches(&self) -> String {
        let mut s: String = Default::default();
        for (name, amt) in self.list.iter() {
            s.push_str(&format!(
                "            {: <40} => Ok(Self::{}),\n",
                amt, name
            ));
        }
        s
    }

    #[allow(dead_code)]
    fn print_all(&self) {
        println!("-- List --");
        self.print_list();

        println!("\n-- enum {{}} --\n{}", self.gen_enum_variants());
        println!("\n-- ::all() --\n{}", self.gen_all_variants());
        println!("\n-- ::amount() --\n{}", self.gen_name_to_amount_matches());
        println!("\n-- ::try_from() --\n{}", self.gen_try_from_matches());
    }

    #[allow(dead_code)]
    fn print_list(&self) {
        for (name, amt) in self.list.iter() {
            println!("{: <15} --> {}", name, amt);
        }
        println!("\ntotal # of denominations: {}", self.list.len());
    }
}
