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
