# Multisig protocol, version 1

Each message is the JSON value of one `ghostly.chat.send` (an `apps/1` data frame), at most 16 KiB as UTF-8:

```json
{"p": "multisig", "v": 1, "k": "<kind>", ...}
```

| kind | fields | meaning |
|---|---|---|
| `hello` | `w`: 16 hex chars or `null`; `re`: `1` (optional) | Sent when the app starts. `w` is the sender's wallet id. `re: 1` marks an answer to a hello; an answer is never answered |
| `psbt` | `id`: 64 hex; `n`, `of`: integers, `0 ≤ n < of ≤ 16`; `d`: base64, 1-12000 chars | Part `n` of a PSBT. `id` is its unsigned txid |
| `ack` | `id`: 64 hex; `m`: 0-15 | "I hold transaction `id`; it still misses `m` signatures" |

## Wallet id

First 16 hex characters of SHA-256 over the canonical descriptor: script type, threshold, `sorted` flag, then for
each key `fingerprint/origin]xpub/steps`, keys sorted for `sortedmulti`. Only the id is sent: the descriptor never is.
Different ids show "Your contact has a different wallet" and nothing is adopted from the peer.

## Rules for a receiver

- Check the size first, then every field. Refuse the whole message on any bad field; ignore unknown fields.
- `v` above 1: show "newer version", drop the message.
- Hold parts of one `id` at a time. A part of another `id`, or another `of`, starts over.
- A whole PSBT whose unsigned txid is not `id` is refused.
- A PSBT with the txid already held is merged (signatures added). A different txid is never merged: the person
  chooses to keep theirs or replace it.
- Answer every whole PSBT with an `ack`.

`chat.send` only delivers while the contact has the app open. The sender keeps a PSBT queued and sends it when it
sees the contact's `hello`.
