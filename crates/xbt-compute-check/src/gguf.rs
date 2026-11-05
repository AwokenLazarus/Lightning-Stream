//! The part of a GGUF file the work meter reads: its header, with its numbers and short strings and
//! every tensor's name and shape. Nothing past the header is read, so a file cut after its header
//! is enough and an operator needs none of the weights.

use std::collections::BTreeMap;
use std::io::{self, BufReader, Read};
use std::path::Path;

/// Most tensors, keys and bytes of one string the reader takes: a damaged file is refused, not followed.
const MAX_TENSORS: u64 = 1 << 24;
const MAX_KEYS: u64 = 1 << 20;
const MAX_STRING: u64 = 1 << 26;
/// Strings kept for the caller; a longer one (a chat template) is read past.
const KEPT_STRING: u64 = 256;
/// Most bytes of a key's or a tensor's name.
const MAX_NAME: u64 = 1 << 16;
const MAX_DIMS: u32 = 8;

const STRING: u32 = 8;
const ARRAY: u32 = 9;

#[derive(Clone, Debug, PartialEq)]
pub struct Tensor {
    pub name: String,
    pub dims: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Header {
    pub strings: BTreeMap<String, String>,
    pub numbers: BTreeMap<String, u64>,
    pub tensors: Vec<Tensor>,
}

fn bad(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

fn u32_of(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn u64_of(r: &mut impl Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn skip(r: &mut impl Read, n: u64) -> io::Result<()> {
    if io::copy(&mut r.by_ref().take(n), &mut io::sink())? == n {
        Ok(())
    } else {
        Err(bad("the file ends inside its header"))
    }
}

fn string_of(r: &mut impl Read) -> io::Result<String> {
    let n = u64_of(r)?;
    if n > MAX_NAME {
        return Err(bad(format!("a name of {n} bytes")));
    }
    let mut b = vec![0u8; n as usize];
    r.read_exact(&mut b)?;
    String::from_utf8(b).map_err(|_| bad("a name that is not text"))
}

/// Bytes of a value of a fixed-size type.
fn fixed_size(ty: u32) -> io::Result<u64> {
    Ok(match ty {
        0 | 1 | 7 => 1,
        2 | 3 => 2,
        4..=6 => 4,
        10..=12 => 8,
        _ => return Err(bad(format!("a value of type {ty}"))),
    })
}

fn skip_string(r: &mut impl Read) -> io::Result<()> {
    let n = u64_of(r)?;
    if n > MAX_STRING {
        return Err(bad(format!("a string of {n} bytes")));
    }
    skip(r, n)
}

fn skip_value(r: &mut impl Read, ty: u32) -> io::Result<()> {
    match ty {
        STRING => skip_string(r),
        ARRAY => {
            let (elem, n) = (u32_of(r)?, u64_of(r)?);
            match elem {
                STRING => (0..n).try_for_each(|_| skip_string(r)),
                ARRAY => Err(bad("an array of arrays")),
                _ => skip(r, fixed_size(elem)?.checked_mul(n).ok_or_else(|| bad("an array too long"))?),
            }
        }
        _ => skip(r, fixed_size(ty)?),
    }
}

/// Reads the header of the GGUF file at `path`.
pub fn read(path: &Path) -> io::Result<Header> {
    read_from(&mut BufReader::new(std::fs::File::open(path)?))
}

pub fn read_from(r: &mut impl Read) -> io::Result<Header> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != b"GGUF" {
        return Err(bad("not a GGUF file"));
    }
    let version = u32_of(r)?;
    if version < 2 {
        return Err(bad(format!("GGUF version {version}")));
    }
    let (tensors, keys) = (u64_of(r)?, u64_of(r)?);
    if tensors > MAX_TENSORS || keys > MAX_KEYS {
        return Err(bad(format!("{tensors} tensors and {keys} keys")));
    }
    let mut h = Header::default();
    for _ in 0..keys {
        let key = string_of(r)?;
        let ty = u32_of(r)?;
        match ty {
            // the unsigned and signed integers the numbers of a model are
            2 | 3 => {
                let mut b = [0u8; 2];
                r.read_exact(&mut b)?;
                h.numbers.insert(key, u16::from_le_bytes(b) as u64);
            }
            4 | 5 => {
                let v = u32_of(r)?;
                h.numbers.insert(key, v as u64);
            }
            10 | 11 => {
                let v = u64_of(r)?;
                h.numbers.insert(key, v);
            }
            STRING => {
                let n = u64_of(r)?;
                if n > MAX_STRING {
                    return Err(bad(format!("a string of {n} bytes")));
                }
                if n <= KEPT_STRING {
                    let mut b = vec![0u8; n as usize];
                    r.read_exact(&mut b)?;
                    if let Ok(s) = String::from_utf8(b) {
                        h.strings.insert(key, s);
                    }
                } else {
                    skip(r, n)?;
                }
            }
            _ => skip_value(r, ty)?,
        }
    }
    for _ in 0..tensors {
        let name = string_of(r)?;
        let n = u32_of(r)?;
        if n > MAX_DIMS {
            return Err(bad(format!("{name}: {n} dimensions")));
        }
        let dims = (0..n).map(|_| u64_of(r)).collect::<io::Result<Vec<u64>>>()?;
        // its type and where its data is: the data is not read
        u32_of(r)?;
        u64_of(r)?;
        h.tensors.push(Tensor { name, dims });
    }
    Ok(h)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A GGUF header, as a writer of one lays it out.
    pub(crate) fn header_bytes(numbers: &[(&str, u32)], strings: &[(&str, &str)], tensors: &[(&str, &[u64])]) -> Vec<u8> {
        let mut b = b"GGUF".to_vec();
        b.extend(3u32.to_le_bytes());
        b.extend((tensors.len() as u64).to_le_bytes());
        // the three kinds of value, and an array of strings to be read past, as a vocabulary is
        b.extend(((numbers.len() + strings.len() + 1) as u64).to_le_bytes());
        let text = |b: &mut Vec<u8>, s: &str| {
            b.extend((s.len() as u64).to_le_bytes());
            b.extend(s.as_bytes());
        };
        for (k, v) in numbers {
            text(&mut b, k);
            b.extend(4u32.to_le_bytes());
            b.extend(v.to_le_bytes());
        }
        for (k, v) in strings {
            text(&mut b, k);
            b.extend(STRING.to_le_bytes());
            text(&mut b, v);
        }
        text(&mut b, "tokenizer.ggml.tokens");
        b.extend(ARRAY.to_le_bytes());
        b.extend(STRING.to_le_bytes());
        b.extend(2u64.to_le_bytes());
        text(&mut b, "a");
        text(&mut b, "b");
        for (name, dims) in tensors {
            text(&mut b, name);
            b.extend((dims.len() as u32).to_le_bytes());
            dims.iter().for_each(|d| b.extend(d.to_le_bytes()));
            b.extend(0u32.to_le_bytes());
            b.extend(0u64.to_le_bytes());
        }
        b
    }

    #[test]
    fn reads_the_numbers_strings_and_tensors_and_nothing_past_them() {
        let bytes = header_bytes(&[("x.block_count", 2)], &[("general.architecture", "x")], &[("blk.0.a", &[3, 4]), ("output.weight", &[5])]);
        let h = read_from(&mut bytes.as_slice()).unwrap();
        assert_eq!(h.numbers["x.block_count"], 2);
        assert_eq!(h.strings["general.architecture"], "x");
        assert_eq!(h.tensors, vec![Tensor { name: "blk.0.a".into(), dims: vec![3, 4] }, Tensor { name: "output.weight".into(), dims: vec![5] }]);
    }

    #[test]
    fn a_file_that_is_not_gguf_or_stops_short_is_refused() {
        assert!(read_from(&mut b"nope....".as_slice()).is_err());
        let bytes = header_bytes(&[], &[], &[("blk.0.a", &[3, 4])]);
        assert!(read_from(&mut &bytes[..bytes.len() - 3]).is_err());
    }
}
