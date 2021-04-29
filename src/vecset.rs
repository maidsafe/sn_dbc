#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VecSet<T>(Vec<T>);

impl<T> Default for VecSet<T> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl<T: Eq> VecSet<T> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert(&mut self, x: T) -> bool {
        if self.contains(&x) {
            false
        } else {
            self.0.push(x);
            true
        }
    }

    pub fn remove(&mut self, x: &T) -> bool {
        if let Some(idx) = self.0.iter().position(|xx| xx == x) {
            self.0.remove(idx);
            true
        } else {
            false
        }
    }

    pub fn contains(&self, x: &T) -> bool {
        self.iter().any(|xx| x == xx)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<T> IntoIterator for VecSet<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Eq> std::iter::FromIterator<T> for VecSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = Self::default();
        for i in iter {
            set.insert(i);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;
    use std::collections::BTreeSet;

    #[quickcheck]
    fn prop_identical_to_btree_set(instructions: Vec<(u8, u8)>) {
        let mut vec_set = VecSet::default();
        let mut btree_set = BTreeSet::default();

        for (instruction, val) in instructions {
            match instruction % 5 {
                0 => {
                    // insert
                    assert_eq!(vec_set.insert(val), btree_set.insert(val));
                }
                1 => {
                    // contains_key
                    assert_eq!(vec_set.contains(&val), btree_set.contains(&val));
                }
                2 => {
                    // len
                    assert_eq!(vec_set.len(), btree_set.len());
                }
                3 => {
                    // collect
                    assert_eq!(vec_set.iter().cloned().collect::<BTreeSet<_>>(), btree_set);
                }
                4 => {
                    // remove
                    assert_eq!(vec_set.remove(&val), btree_set.remove(&val));
                }
                _ => panic!(),
            }
        }
    }
}
