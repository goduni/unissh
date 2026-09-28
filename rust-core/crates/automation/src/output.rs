use super::{run_json, Result, Run, ToolError, PAGE_BYTES};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

struct Chunk {
    stderr: bool,
    data: Vec<u8>,
}

/// Published chunks are immutable, keeping existing integer cursors valid.
/// Each stream retains at most three bytes of an incomplete UTF-8 scalar.
#[derive(Default)]
pub(super) struct OutputBuffer {
    chunks: Vec<Chunk>,
    pending: [Vec<u8>; 2],
}
impl OutputBuffer {
    pub(super) fn has_more(&self, cursor: &str) -> bool {
        cursor
            .parse::<usize>()
            .is_ok_and(|cursor| cursor < self.chunks.len())
    }
    pub(super) fn push(&mut self, stderr: bool, bytes: &[u8]) -> usize {
        // Reserve one final chunk for each stream's incomplete scalar.
        if self.chunks.len() >= 4094 || bytes.is_empty() {
            return 0;
        }
        let stream = usize::from(stderr);
        let mut data = std::mem::take(&mut self.pending[stream]);
        let prior = data.len();
        data.extend_from_slice(bytes);
        let mut offset = 0;
        while offset < data.len() && self.chunks.len() < 4094 {
            let end = (offset + 16 * 1024).min(data.len());
            let part = &data[offset..end];
            let complete = match std::str::from_utf8(part) {
                Err(error) if error.error_len().is_none() => error.valid_up_to(),
                _ => part.len(),
            };
            if complete == 0 {
                // At most three bytes, only at the end of the input; otherwise
                // the full 16 KiB slice necessarily contains a complete scalar.
                self.pending[stream].extend_from_slice(part);
                offset = end;
            } else {
                self.chunks.push(Chunk {
                    stderr,
                    data: part[..complete].to_vec(),
                });
                offset += complete;
            }
        }
        offset.saturating_sub(prior)
    }
    pub(super) fn flush(&mut self) {
        for (stream, bytes) in self.pending.iter_mut().enumerate() {
            if !bytes.is_empty() {
                self.chunks.push(Chunk {
                    stderr: stream == 1,
                    data: std::mem::take(bytes),
                });
            }
        }
    }
}

pub(super) fn page(id: &str, run: &Run, cursor: Option<&str>) -> Result<Value> {
    let cursor = cursor
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_| ToolError::OutputExpired)?;
    if cursor > run.output.chunks.len() {
        return Err(ToolError::OutputExpired);
    }
    let mut bytes = 0;
    let mut next = cursor;
    let mut chunks = Vec::new();
    for chunk in run.output.chunks.iter().skip(cursor) {
        if bytes + chunk.data.len() > PAGE_BYTES {
            break;
        }
        let text = std::str::from_utf8(&chunk.data)
            .ok()
            .filter(|text| !text.contains('\0'));
        let (encoding, data) = match text {
            Some(text) => ("utf8", text.to_owned()),
            None => ("base64", STANDARD.encode(&chunk.data)),
        };
        chunks.push(json!({"cursor":next.to_string(),"stream":if chunk.stderr {"stderr"} else {"stdout"},"encoding":encoding,"data":data}));
        bytes += chunk.data.len();
        next += 1;
    }
    let mut result = run_json(id, run);
    result["chunks"] = json!(chunks);
    result["next_cursor"] = json!(next.to_string());
    result["truncated"] = json!(run.truncated);
    result["exit_code"] = json!(run.exit_code);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_utf8_packet_splits_and_internal_chunk_boundaries_are_lossless() {
        let text = "hello 🌍, Привет, 日本語\n";
        for split in 0..=text.len() {
            let mut output = OutputBuffer::default();
            assert_eq!(output.push(false, &text.as_bytes()[..split]), split);
            let old = output
                .chunks
                .iter()
                .map(|c| c.data.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                output.push(false, &text.as_bytes()[split..]),
                text.len() - split
            );
            output.flush();
            assert!(output
                .chunks
                .iter()
                .all(|c| std::str::from_utf8(&c.data).is_ok()));
            assert_eq!(
                output
                    .chunks
                    .iter()
                    .flat_map(|c| c.data.iter().copied())
                    .collect::<Vec<_>>(),
                text.as_bytes()
            );
            for (index, bytes) in old.iter().enumerate() {
                assert_eq!(&output.chunks[index].data, bytes);
            }
        }
        let text = "🌍".repeat(20000);
        let mut output = OutputBuffer::default();
        assert_eq!(output.push(false, text.as_bytes()), text.len());
        assert!(output
            .chunks
            .iter()
            .all(|c| std::str::from_utf8(&c.data).is_ok()));
        assert_eq!(
            output.chunks.iter().map(|c| c.data.len()).sum::<usize>(),
            text.len()
        );
    }

    #[test]
    fn binary_and_incomplete_final_scalars_are_never_replaced_or_lost() {
        for bytes in [b"ok\0binary\xff".as_slice(), b"ok\xf0\x9f", b"\xe2"] {
            for split in 0..=bytes.len() {
                let mut output = OutputBuffer::default();
                assert_eq!(output.push(false, &bytes[..split]), split);
                assert_eq!(output.push(false, &bytes[split..]), bytes.len() - split);
                output.flush();
                assert_eq!(
                    output
                        .chunks
                        .iter()
                        .flat_map(|c| c.data.iter().copied())
                        .collect::<Vec<_>>(),
                    bytes
                );
                assert!(output.pending.iter().all(Vec::is_empty));
            }
        }
    }

    #[test]
    fn packet_fragment_limit_accounts_for_buffered_bytes_and_reserves_flush_space() {
        let mut output = OutputBuffer::default();
        let mut saved = output.push(true, b"\xf0\x9f");
        for _ in 0..5000 {
            saved += output.push(false, b"x");
        }
        output.flush();
        assert!(output.chunks.len() <= 4096);
        assert_eq!(
            output.chunks.iter().map(|c| c.data.len()).sum::<usize>(),
            saved
        );
    }
}
