# One-time codes (TOTP)

prive reads two-factor secrets from the places KeePass apps put them, in this order:

1. The `otp` field, as written by KeePassXC, KeePassDX and Strongbox. It may hold:
   - an `otpauth://totp/...` URI, with `secret`, `period`, `digits`, `algorithm` and
     `encoder=steam` honoured;
   - the older KeeOtp plugin form, `key=BASE32&step=30&size=6&otpHashMode=sha256`;
   - a bare base32 secret (30-second, 6-digit, SHA-1 codes).
2. KeePass 2.47+ native fields: `TimeOtp-Secret-Base32`, `TimeOtp-Secret-Hex`,
   `TimeOtp-Secret-Base64` or `TimeOtp-Secret`, with `TimeOtp-Length`, `TimeOtp-Period` and
   `TimeOtp-Algorithm` (`HMAC-SHA-1`, `HMAC-SHA-256`, `HMAC-SHA-512`).
3. Legacy KeePassXC fields: `TOTP Seed`, with `TOTP Settings` such as `30;6`, or `30;S` for
   Steam Guard.

Supported: SHA-1, SHA-256 and SHA-512; 4 to 10 digits; any period; Steam Guard's 5-character
codes. Not supported: HOTP (counter-based codes), because using one means writing the counter
back to the database.

Codes are checked against the RFC 6238 test vectors in the test suite.

## Getting a code

```bash
prive otp Work/GitHub                    # the current code
prive otp Work/GitHub --clip             # copied, cleared after the clipboard timeout
prive otp Work/GitHub --min-validity 10  # never one about to expire: waits for the next
prive otp Work/GitHub --next             # the one after, for sites that ask for two
prive otp Work/GitHub --watch            # keeps showing it, like an authenticator app
prive codes                              # every entry's current code at once
```

`--watch` redraws one line until Ctrl-C, with a bar of the time left:

```
123456  [##########----------]  15 s
```

It needs a terminal, and says so before asking for any password.

## When prive can't read a code

`prive otp` exits with 3 when an entry has no one-time code at all. When the entry has code
settings prive doesn't understand (a field it can't decode, or values out of range), it says
so and exits with 1, so a typo in the settings isn't mistaken for "no code".

## Moving a code to a phone or another app

```bash
prive otp Work/GitHub --qr     # a QR code in the terminal: scan it with the authenticator app
prive otp Work/GitHub --uri    # otpauth://totp/GitHub:demo?secret=...&period=30&digits=6&...
```

Both show the secret itself: anyone who sees the QR code or the URI can make your codes.
They work for every stored form above, so a code saved in KeePass 2's own fields can still be
moved to an app that only reads otpauth URIs.

