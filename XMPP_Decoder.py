import base64
import hashlib
import hmac
import argparse
from concurrent.futures import ThreadPoolExecutor
from typing import List
from colorama import Fore, Style, init

init(autoreset=True)

# === Loaders ===

def load_file_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_rules(rule_path: str) -> List[str]:
    try:
        return [''.join([line[i] for i in range(1, len(line), 2)])
                for line in load_file_lines(rule_path) if line.startswith("^")]
    except FileNotFoundError:
        return []

# === SCRAM computation ===

def compute_server_signature(password: str, salt: bytes, iterations: int, auth_msg: bytes) -> str:
    salted = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, iterations, dklen=20)
    server_key = hmac.new(salted, b"Server Key", hashlib.sha1).digest()
    sig = hmac.new(server_key, auth_msg, hashlib.sha1).digest()
    return base64.b64encode(sig).decode()

# === Batch processing ===

def check_batch(words: List[str], prefixes: List[str], offset: int, no_prefix: bool,
                salt: bytes, iterations: int, auth_msg: bytes, expected_sig: str):
    for j, word in enumerate(words):
        for candidate in ([word] if no_prefix else [p + word for p in prefixes]):
            if compute_server_signature(candidate, salt, iterations, auth_msg) == expected_sig:
                print(f"\n{Fore.GREEN}[+] Password found: {Style.BRIGHT}{candidate}")
                print(f"{Fore.CYAN}SHA1 : {hashlib.sha1(candidate.encode()).hexdigest()}")
                exit(0)
        if (offset + j) % 20000 == 0:
            print(f"{Fore.YELLOW}[{offset + j}] Last tested: {word}")

# === Args and execution ===

def banner():
    print(f"""
{Fore.WHITE}{Style.BRIGHT}
----------------------------------
██   ██ ███    ███ ██████  ██████  
 ██ ██  ████  ████ ██   ██ ██   ██ 
  ███   ██ ████ ██ ██████  ██████  
 ██ ██  ██  ██  ██ ██      ██      
██   ██ ██      ██ ██      ██      
----------------------------------

{Fore.MAGENTA}[+] Author : Betelgeuse{Style.RESET_ALL}
{Fore.MAGENTA}[+] Tool	 : Mask Wordlist Generator{Style.RESET_ALL}
{Fore.MAGENTA}[+] Date	 : April 05, 2025{Style.RESET_ALL}
""")


def parse_args():
    p = argparse.ArgumentParser(
        description="SCRAM-SHA1 multithread checker",
        epilog="Example: python scram_checker.py -w wordlist.txt --username alice --client_nonce abc --server_nonce def --salt base64== --iterations 4096 --signature abc123=="
    )
    p.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file (one password per line)")
    p.add_argument("-r", "--rules", help="Optional rule file (lines starting with ^, for prepending)")
    p.add_argument("-t", "--threads", type=int, default=4, help="Number of threads (default: 4)")
    p.add_argument("-b", "--batch", type=int, default=5000, help="Words per batch per thread (default: 5000)")
    p.add_argument("--username", required=True, help="SCRAM username (n=...)")
    p.add_argument("--client_nonce", required=True, help="Client nonce (r=...)")
    p.add_argument("--server_nonce", required=True, help="Server nonce (r=...)")
    p.add_argument("--salt", required=True, help="Salt (base64-encoded)")
    p.add_argument("--iterations", type=int, required=True, help="Iteration count for PBKDF2")
    p.add_argument("--signature", required=True, help="Expected server signature (base64)")
    return p.parse_args()


def run(wordlist: List[str], rules: List[str], args):
    no_prefix = not rules
    salt = base64.b64decode(args.salt)
    nonce = args.client_nonce + args.server_nonce
    auth_msg = f"n={args.username},r={args.client_nonce},r={nonce},s={args.salt},i={args.iterations},c=biws,r={nonce}".encode()

    print(f"{Fore.BLUE}[+] Testing {len(wordlist)} words ({'no rules' if no_prefix else f'{len(rules)} rules'})")

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [
            pool.submit(check_batch, wordlist[i:i + args.batch], rules, i, no_prefix,
                        salt, args.iterations, auth_msg, args.signature)
            for i in range(0, len(wordlist), args.batch)
        ]
        for f in futures:
            f.result()

    print(f"{Fore.RED}[-] No password found.")

def main():
    banner()
    args = parse_args()
    wordlist = load_file_lines(args.wordlist)
    rules = load_rules(args.rules) if args.rules else []
    run(wordlist, rules, args)

if __name__ == "__main__":
    main()
