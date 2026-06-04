//! One JSON message per line, with a size limit so a confused or hostile peer can't make
//! either side hold unbounded data. Lines that may hold secrets are read into memory that is
//! wiped afterwards.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// Large enough for a database of tens of thousands of entries.
pub const MAX_LINE: usize = 64 * 1024 * 1024;

pub fn write<T: Serialize>(w: &mut impl Write, msg: &T) -> Result<()> {
    let mut line = Zeroizing::new(serde_json::to_string(msg)?);
    line.push('\n');
    w.write_all(line.as_bytes())?;
    w.flush()?;
    Ok(())
}

/// Read one message. `Ok(None)` when the other side closed the connection cleanly.
pub fn read<T: DeserializeOwned>(r: &mut dyn BufRead) -> Result<Option<T>> {
    let mut buf = Zeroizing::new(Vec::new());
    let mut limited = std::io::Read::take(r, MAX_LINE as u64 + 1);
    let n = limited
        .read_until(b'\n', &mut buf)
        .context("reading from the agent socket")?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE {
        bail!("agent message too large");
    }
    let msg = serde_json::from_slice(&buf).context("malformed agent message")?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::proto::{Envelope, Request, VERSION};

    #[test]
    fn round_trip_and_clean_close() {
        let mut out = Vec::new();
        write(
            &mut out,
            &Envelope {
                v: VERSION,
                body: Request::Status,
            },
        )
        .unwrap();
        write(
            &mut out,
            &Envelope {
                v: VERSION,
                body: Request::Lock,
            },
        )
        .unwrap();
        let mut input = std::io::Cursor::new(out);
        let a: Envelope<Request> = read(&mut input).unwrap().unwrap();
        let b: Envelope<Request> = read(&mut input).unwrap().unwrap();
        assert!(matches!(a.body, Request::Status));
        assert!(matches!(b.body, Request::Lock));
        assert!(read::<Envelope<Request>>(&mut input).unwrap().is_none());
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        let mut input = std::io::Cursor::new(b"not json\n".to_vec());
        assert!(read::<Envelope<Request>>(&mut input).is_err());
    }
}
