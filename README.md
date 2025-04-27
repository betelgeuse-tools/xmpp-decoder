# SCRAM-SHA1 Multithread Checker

A fast multithreaded tool to crack SCRAM-SHA1 server signatures using a wordlist and optional rules for prefixing.

---

## Features

- Multithreaded password checking
- Rule-based prefixing (optional)
- Supports batch processing
- Colored terminal output (with Colorama)

---

## Example Usage

```bash
python XMPP_Decoder.py -w wordlist.txt --username jhon_doe --client_nonce abc123 --server_nonce def456 --salt SGVsbG9Xb3JsZA== --iterations 4096 --signature AbCdEf123==
```

### Required parameters:

- `-w`, `--wordlist` : Path to your password list (one password per line)
- `--username` : SCRAM username
- `--client_nonce` : Client nonce
- `--server_nonce` : Server nonce
- `--salt` : Base64-encoded salt
- `--iterations` : Iteration count for PBKDF2
- `--signature` : Expected server signature (Base64)

### Optional parameters:

- `-r`, `--rules` : Path to a rule file (each line starting with `^`, one prefix character every two characters)
- `-t`, `--threads` : Number of threads to use (default: 4)
- `-b`, `--batch` : Number of passwords processed per thread at once (default: 5000)

### Example

```bash
python scram_checker.py -w rockyou.txt -r rules.txt --username jhon_doe --client_nonce abc123 --server_nonce def456 --salt SGVsbG9Xb3JsZA== --iterations 4096 --signature AbCdEf123==
```

This command will:
- Load the wordlist `rockyou.txt`
- Apply prefixes from `rules.txt` to every password
- Compute the SCRAM-SHA1 signature for each candidate
- Compare it against the expected server signature
- Display the password if found

---

## Installation

```bash
git clone https://github.com/betelgeuse-tools/xmpp-decoder.git
cd xmpp-decoder
pip install -r requirements.txt
```

**Required packages** (also can be installed manually):

```
pip install colorama
```

---


## License

This project is licensed under the **MIT License** — feel free to use, modify, and share!

---

## Author

> Made with ❤️ by **Betelgeuse** (April 09, 2025)
