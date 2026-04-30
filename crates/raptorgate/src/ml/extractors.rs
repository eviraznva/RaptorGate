pub fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    
    let mut counts = [0u32; 256];
    
    for &b in bytes {
        counts[b as usize] += 1;
    }
    
    let len = bytes.len() as f32;
    let mut h = 0.0f32;
    
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        
        let p = *c as f32 / len;
        
        h -= p * p.log2();
    }
    
    h
}

pub fn shannon_entropy_str(s: &str) -> f32 {
    shannon_entropy(s.as_bytes())
}

fn fnv1a(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    
    h
}

pub fn hash_bucket(s: &str, buckets: u32) -> u32 {
    if buckets == 0 {
        return 0;
    }
    
    fnv1a(s.as_bytes()) % buckets
}

pub fn normalized_hash_bucket(s: &str, buckets: u32) -> f32 {
    if buckets == 0 {
        return 0.0;
    }
    
    hash_bucket(s, buckets) as f32 / buckets as f32
}

pub fn log1p_f32(x: f32) -> f32 {
    x.ln_1p()
}

pub fn label_max_len(qname: &str) -> usize {
    qname.split('.').map(str::len).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uniform_higher_than_repeat() {
        let h_repeat = shannon_entropy_str("aaaaaaaa");
        let h_uniform = shannon_entropy_str("abcdefgh");
        assert!(h_uniform > h_repeat);
    }

    #[test]
    fn entropy_empty_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn hash_bucket_stable() {
        let a = hash_bucket("example.com", 4096);
        let b = hash_bucket("example.com", 4096);
        assert_eq!(a, b);
        assert!(a < 4096);
    }

    #[test]
    fn label_max() {
        assert_eq!(label_max_len("a.bbb.cc"), 3);
        assert_eq!(label_max_len(""), 0);
    }

    #[test]
    fn log1p_zero() {
        assert_eq!(log1p_f32(0.0), 0.0);
    }
}
