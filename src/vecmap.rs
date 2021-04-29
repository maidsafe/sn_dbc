#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VecMap<K, V>(Vec<(K, V)>);

impl<K, V> Default for VecMap<K, V> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl<K: Eq, V> VecMap<K, V> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        self.iter().find(|(kk, _)| kk == k).map(|(_, v)| v)
    }

    pub fn contains_key(&self, k: &K) -> bool {
        self.get(&k).is_some()
    }

    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        let old = self.remove(&k);
        self.0.push((k, v));
        old
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        if let Some(idx) = self.0.iter().position(|(kk, _)| kk == k) {
            let (_, v) = self.0.remove(idx);
            Some(v)
        } else {
            None
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<K, V> IntoIterator for VecMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<K: Eq, V> std::iter::FromIterator<(K, V)> for VecMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::default();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;
    use std::collections::BTreeMap;

    #[quickcheck]
    fn prop_identical_to_btree_map(instructions: Vec<(u8, u8, u8)>) {
        let mut vec_map = VecMap::default();
        let mut btree_map = BTreeMap::default();

        for (instruction, key, value) in instructions {
            match instruction % 6 {
                0 => {
                    // insert
                    assert_eq!(vec_map.insert(key, value), btree_map.insert(key, value));
                }
                1 => {
                    // contains_key
                    assert_eq!(vec_map.contains_key(&key), btree_map.contains_key(&key));
                }
                2 => {
                    // get
                    assert_eq!(vec_map.get(&key), btree_map.get(&key));
                }
                3 => {
                    // len
                    assert_eq!(vec_map.len(), btree_map.len());
                }
                4 => {
                    // collect
                    assert_eq!(
                        vec_map.iter().cloned().collect::<BTreeMap<_, _>>(),
                        btree_map
                    );
                }
                5 => {
                    // remove
                    assert_eq!(vec_map.remove(&key), btree_map.remove(&key));
                }
                _ => panic!(),
            }
        }
    }
}
