// this module will generate character frequency for texts

use std::collections::HashMap;

#[derive(Debug)]
pub struct CharFreq {
    counts: HashMap<char, usize>,
    total: usize
}

impl CharFreq {
    pub fn for_english() -> CharFreq {
        CharFreq {
        	counts: vec![
                (' ', 12802),
                ('e', 12702),
                ('t', 9056),
                ('a', 8167),
                ('o', 7507),
                ('i', 6966),
                ('n', 6749),
                ('s', 6327),
                ('h', 6094),
                ('r', 5987),
                ('d', 4253),
                ('l', 4025),
                ('c', 2782),
                ('u', 2758),
                ('m', 2406),
                ('w', 2361),
                ('f', 2228),
                ('g', 2015),
                ('y', 1974),
                ('p', 1929),
                ('b', 1492),
                ('v', 978),
                ('k', 772),
                ('j', 153),
                ('x', 150),
                ('q', 95),
                ('z', 74),
            ].into_iter().collect(),
            total: 100_000,
        }
    }

    pub fn new() -> CharFreq {
        CharFreq { counts: HashMap::new(), total: 0}
    }

    pub fn count(&mut self, c: char) {
        let c = c.to_lowercase().next().unwrap();
        let count = self.counts.entry(c).or_insert(0);
        *count += 1;
        self.total += 1;
    }

    pub fn count_all(&mut self, s: &str)  {
        for c in s.chars() {
            self.count(c);
        }
    }

    pub fn dist(&self, other: &Self) -> f32 {
        let total = self.total as f32;
        let other_total = other.total as f32;

        let mut diff = 0.0;
        for (k, &v) in self.counts.iter() {
            let p = v as f32 / total;
            let op = *other.counts.get(k).unwrap_or(&0) as f32 / other_total;
            diff += (p - op).abs();
        }

        // append to diff other chars that never occur in this freq as well
        for (k, &v) in other.counts.iter() {
            if self.counts.contains_key(k) {
            	continue;
            }

            let p = v as f32 / other_total;
            diff += p;
        }
        diff
    }

    pub fn dist_from_string(&self, s: &str) -> f32 {
        let mut other = CharFreq::new();
        other.count_all(s);
        self.dist(&other)
    }
}

pub fn kv_parse(input: String) -> HashMap<String, String>{
    let mut retval: HashMap<String, String> = HashMap::new();
    for item in input.split('&') {
        let pair: Vec<&str> = item.split('=').collect();
        let mut str_pair = pair.iter().map(|s| String::from(*s));
        retval.insert(str_pair.next().unwrap(), str_pair.next().unwrap());
    }
    retval
}

pub fn kv_encode(map: HashMap<String, String>) -> String {
    let mut retval = vec!();
    for (k,v) in map.iter() {
        let to_insert = format!("{}={}", k, v);
        retval.push(to_insert);
    }
    retval.join("&")
}

pub fn profile_for(email: &str) -> String {
    let sanitized_email = email.replace('@', "").replace('=',"");
    let obj: HashMap<String, String> = [
        ("email".to_string(), sanitized_email),
        ("uid".to_string(), "10".to_string()),
        ("role".to_string(), "user".to_string())
    ].iter().cloned().collect();

    kv_encode(obj)
}