# Access Code Algorithm

From a **single private key** (raw bytes, not a mnemonic) and a **name** to a
stable **6-digit numeric access code**. The same name always produces the
same code. There is no counter, no timestamp, no expiry — the name is the
only input besides the key.

```
name  ──┐
        ├──►  6-digit access code   (deterministic, repeatable forever)
key   ──┘
```

## Inputs

| Input | Type | Notes |
|-------|------|-------|
| `private_key` | 32 bytes | The one and only secret. |
| `name` | UTF-8 string | Used exactly as given — no trimming, lowercasing, or normalization. |

## Output

A 6-digit decimal string, e.g. `"201195"`. Range `000000`–`999999`.

## The algorithm — one step

```
digest = HMAC-SHA256(key = private_key, data = name_bytes)
code   = zero-padded decimal of ( int(digest[0..4]) mod 1,000,000 ) to 6 digits
```

HMAC-SHA256 always outputs 32 bytes. `digest[0..4]` means the **first 4
bytes** of that output, read as one big-endian unsigned integer. Reducing
mod 1,000,000 squeezes it into the 6-digit range.

## Worked example

With `private_key` = `000102...1e1f` (bytes 0x00 through 0x1f) and
`name = "alice"`:

```
digest        = 6eefad2b ed97b6d9 3ee663d6 7a44b460 ...   (32 bytes total)
digest[0..4]  = 6e ef ad 2b                          (first 4 bytes only)
as integer    = 1,861,201,195
mod 1,000,000 = 201,195
zero-padded   = "201195"
```

`"alice"` → `201195`, every single time. `"bob"` → `464628`.

## Pseudocode

```
function access_code(private_key: bytes, name: string) -> string:
    digest = HMAC-SHA256(private_key, utf8(name))
    n      = read_u32_be(digest[0:4])
    return format("%06d", n mod 1000000)
```

## Reference implementations

Rust:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn access_code(private_key: &[u8], name: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(private_key).unwrap();
    mac.update(name.as_bytes());
    let digest = mac.finalize().into_bytes();

    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", n % 1_000_000)
}
```

Python:

```python
import hmac, hashlib

def access_code(private_key: bytes, name: str) -> str:
    digest = hmac.new(private_key, name.encode(), hashlib.sha256).digest()
    n = int.from_bytes(digest[:4], "big")
    return f"{n % 1_000_000:06d}"
```

TypeScript (Node):

```ts
import { createHmac } from "crypto";

export function accessCode(privateKey: Buffer, name: string): string {
  const digest = createHmac("sha256", privateKey).update(name, "utf8").digest();
  const n = digest.readUInt32BE(0);
  return String(n % 1_000_000).padStart(6, "0");
}
```

## Test vector

```
private_key (hex) = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

name "alice" -> 201195
name "bob"   -> 464628
name "alice" -> 201195   (same name, same code, always)
```

## Properties

- **Deterministic** — same key + same name = same code, indefinitely. No
  expiry, no rollover, no state.
- **One secret** — only the private key is needed to compute any code.
- **Different names, different codes** — the name itself separates cases
  inside the HMAC; a changed or misspelled name yields a completely
  different code.
- **Verifiable offline** — anyone holding the private key can recompute the
  code for a name with no network call.

## Security notes

- 6 digits = one million possibilities. The code is a convenience handle,
  not a high-entropy secret; rate-limit verification attempts.
- Compare a user-supplied code in constant time (`ConstantTimeEq` or
  equivalent), never with `==`.
- If the key is ever compromised, replacing it changes every code at once.
- Keep the private key in memory only, zeroized when done.
