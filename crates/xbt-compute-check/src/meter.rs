//! What a machine of a split does for each token, as active parameters: what it multiplies per token.
//! A lender is paid for the work its layers do, not for how fast its machine does it.
//!
//! Every tensor of a layer counts whole, except a mixture-of-experts layer's experts, of which a
//! token uses only `expert_used_count` of `expert_count`. The token embedding is one row per token,
//! on the machine with the first layer. The output head multiplies by the whole vocabulary, on the
//! machine with the last layer: a tied head is the embedding's matrix used again.
//!
//! A prompt's tokens do not reach the head but the last, so the machine with the head is paid a little
//! more than it did for prompts. Earnings are not split into prompt and answer, and the head's share
//! is what an answer's tokens cost.

use crate::gguf::{Header, Tensor};

#[derive(Clone, Debug, PartialEq)]
pub struct Work {
    /// Active parameters of each layer, by its index.
    pub layers: Vec<u128>,
    pub embed: u128,
    pub head: u128,
}

fn params(t: &Tensor) -> u128 {
    t.dims.iter().map(|d| *d as u128).product()
}

impl Work {
    pub fn from_header(h: &Header) -> Result<Work, String> {
        let arch = h.strings.get("general.architecture").ok_or("the file names no architecture")?;
        let number = |k: &str| h.numbers.get(&format!("{arch}.{k}")).copied();
        let n = number("block_count").ok_or("the file names no block_count")? as usize;
        if n == 0 || n > 1 << 16 {
            return Err(format!("{n} layers"));
        }
        // a model with no experts has neither number
        let (used, count) = (number("expert_used_count").unwrap_or(1).max(1) as u128, number("expert_count").unwrap_or(1).max(1) as u128);
        let mut w = Work { layers: vec![0; n], embed: 0, head: 0 };
        let mut matrix = 0;
        let mut own_head = false;
        for t in &h.tensors {
            if let Some(rest) = t.name.strip_prefix("blk.") {
                let (i, field) = rest.split_once('.').ok_or_else(|| format!("tensor {}", t.name))?;
                let i: usize = i.parse().map_err(|_| format!("tensor {}", t.name))?;
                let layer = w.layers.get_mut(i).ok_or_else(|| format!("tensor {} of a model with {n} layers", t.name))?;
                *layer += if field.contains("_exps") { params(t) * used / count } else { params(t) };
            } else if t.name == "token_embd.weight" {
                // [width, vocabulary]: a row per token
                w.embed = *t.dims.first().unwrap_or(&0) as u128;
                matrix = params(t);
            } else if t.name == "output.weight" {
                w.head += params(t);
                own_head = true;
            } else if t.name == "output_norm.weight" {
                w.head += params(t);
            }
        }
        if !own_head {
            w.head += matrix;
        }
        if w.layers.contains(&0) {
            return Err("a layer with no tensors: the file is not the whole model's header".into());
        }
        Ok(w)
    }

    /// Active parameters of the stage with layers `[start, end)`.
    pub fn stage(&self, start: u32, end: u32) -> u128 {
        let mut sum: u128 = self.layers[start as usize..end as usize].iter().sum();
        if start == 0 {
            sum += self.embed;
        }
        if end as usize == self.layers.len() {
            sum += self.head;
        }
        sum
    }

    pub fn total(&self) -> u128 {
        self.stage(0, self.layers.len() as u32)
    }
}

/// `amount` split by `weights`, the parts summing to `amount` exactly: the largest remainders take
/// what rounding down left, ties to the earlier. All weights zero: nothing can be split, so `None`.
pub fn split(amount: u64, weights: &[u128]) -> Option<Vec<u64>> {
    let total: u128 = weights.iter().sum();
    if total == 0 {
        return None;
    }
    let mut parts: Vec<u64> = weights.iter().map(|w| (amount as u128 * w / total) as u64).collect();
    let mut left = amount - parts.iter().sum::<u64>();
    let mut order: Vec<usize> = (0..weights.len()).collect();
    order.sort_by_key(|i| (std::cmp::Reverse(amount as u128 * weights[*i] % total), *i));
    for i in order {
        if left == 0 {
            break;
        }
        parts[i] += 1;
        left -= 1;
    }
    Some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gguf::read_from;
    use crate::gguf::tests::header_bytes;

    fn dense() -> Header {
        let bytes = header_bytes(
            &[("qwen3.block_count", 2)],
            &[("general.architecture", "qwen3")],
            &[("token_embd.weight", &[10, 100]), ("blk.0.attn_q.weight", &[10, 10]), ("blk.0.ffn_up.weight", &[10, 20]), ("blk.1.attn_q.weight", &[10, 10]),
              ("blk.1.ffn_up.weight", &[10, 20]), ("output_norm.weight", &[10])],
        );
        read_from(&mut bytes.as_slice()).unwrap()
    }

    #[test]
    fn a_dense_models_work_is_its_layers_a_row_of_the_embedding_and_the_tied_head() {
        let w = Work::from_header(&dense()).unwrap();
        assert_eq!(w.layers, vec![300, 300]);
        assert_eq!(w.embed, 10);
        assert_eq!(w.head, 1000 + 10, "the tied matrix, and the norm");
        assert_eq!(w.stage(0, 1), 310, "the first machine: its layer and the row it looks up");
        assert_eq!(w.stage(1, 2), 300 + 1010, "the last machine: its layer and the head");
        assert_eq!(w.total(), w.stage(0, 1) + w.stage(1, 2));
    }

    #[test]
    fn a_mixture_of_experts_counts_only_the_experts_a_token_uses() {
        let bytes = header_bytes(
            &[("qwen3moe.block_count", 1), ("qwen3moe.expert_count", 8), ("qwen3moe.expert_used_count", 2)],
            &[("general.architecture", "qwen3moe")],
            &[("token_embd.weight", &[10, 100]), ("blk.0.attn_q.weight", &[10, 10]), ("blk.0.ffn_gate_inp.weight", &[10, 8]), ("blk.0.ffn_up_exps.weight", &[10, 20, 8]),
              ("output.weight", &[10, 100])],
        );
        let w = Work::from_header(&read_from(&mut bytes.as_slice()).unwrap()).unwrap();
        // the attention, the router whole, and 2 of the 8 experts
        assert_eq!(w.layers, vec![100 + 80 + 1600 * 2 / 8]);
        assert_eq!(w.head, 1000, "its own head, and the embedding's matrix not counted again");
    }

    #[test]
    fn a_header_missing_layers_is_refused() {
        let bytes = header_bytes(&[("x.block_count", 3)], &[("general.architecture", "x")], &[("blk.0.a", &[2]), ("blk.1.a", &[2])]);
        assert!(Work::from_header(&read_from(&mut bytes.as_slice()).unwrap()).is_err());
    }

    #[test]
    fn a_split_sums_exactly_and_follows_the_weights() {
        for amount in [0u64, 1, 2, 3, 7, 1000, 1001, 10_952, u32::MAX as u64] {
            for weights in [vec![1u128, 1, 1], vec![310, 1310], vec![5, 0, 7], vec![1, 1_000_000_000_000]] {
                let parts = split(amount, &weights).unwrap();
                assert_eq!(parts.iter().sum::<u64>(), amount, "{amount} by {weights:?}");
                let total: u128 = weights.iter().sum();
                for (p, w) in parts.iter().zip(&weights) {
                    let fair = amount as u128 * w / total;
                    assert!(*p as u128 == fair || *p as u128 == fair + 1, "{amount} by {weights:?}: {p}");
                }
            }
        }
        assert_eq!(split(10, &[0, 0]), None);
        assert_eq!(split(100, &[1, 3]), Some(vec![25, 75]));
        assert_eq!(split(10, &[1, 1, 1]), Some(vec![4, 3, 3]), "what is left goes to the earlier of equals");
    }
}
