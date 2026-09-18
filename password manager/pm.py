#!/usr/bin/env python3
import sys
import os
import argparse
import secrets
import string
import getpass

from vault_store import create_vault, unlock_vault, VaultError, WrongPasswordError, VaultCorruptError

DEFAULT_VAULT_PATH = "vault.json"


def prompt_master_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            print("Passwords did not match.", file=sys.stderr)
            sys.exit(1)
        if len(pw) < 8:
            print("Master password should be at least 8 characters.", file=sys.stderr)
            sys.exit(1)
    return pw


def cmd_init(args):
    try:
        pw = prompt_master_password(confirm=True)
        create_vault(args.vault, pw)
        print(f"Vault created at {args.vault}")
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _open(args):
    pw = prompt_master_password(confirm=False)
    try:
        return unlock_vault(args.vault, pw)
    except WrongPasswordError:
        print("Error: incorrect master password.", file=sys.stderr)
        sys.exit(1)
    except VaultCorruptError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_add(args):
    vault = _open(args)
    site = input("Site/service: ").strip()
    username = input("Username/email: ").strip()
    use_generated = input("Generate a strong password? [Y/n]: ").strip().lower()
    if use_generated in ("", "y", "yes"):
        length = 20
        password = generate_password(length)
        print(f"Generated password: {password}")
    else:
        password = getpass.getpass("Password: ")
    notes = input("Notes (optional): ").strip()
    entry = vault.add_entry(site, username, password, notes)
    vault.save()
    print(f"Added entry #{entry['id']} for '{site}'.")


def cmd_get(args):
    vault = _open(args)
    entry = vault.get_entry(args.id)
    if not entry:
        print(f"No entry with id {args.id}.", file=sys.stderr)
        sys.exit(1)
    _print_entry(entry, reveal=True)


def cmd_list(args):
    vault = _open(args)
    entries = vault.list_all()
    if not entries:
        print("Vault is empty.")
        return
    for e in entries:
        print(f"[{e['id']}] {e['site']} — {e['username']}")


def cmd_search(args):
    vault = _open(args)
    results = vault.search(args.query)
    if not results:
        print("No matches.")
        return
    for e in results:
        print(f"[{e['id']}] {e['site']} — {e['username']}")


def cmd_delete(args):
    vault = _open(args)
    entry = vault.get_entry(args.id)
    if not entry:
        print(f"No entry with id {args.id}.", file=sys.stderr)
        sys.exit(1)
    confirm = input(f"Delete entry #{entry['id']} ({entry['site']})? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return
    vault.delete_entry(args.id)
    vault.save()
    print("Deleted.")


def cmd_generate(args):
    print(generate_password(args.length))


def generate_password(length: int = 20) -> str:
    """Cryptographically secure random password using the `secrets` module
    (never `random` — that's not safe for anything security-sensitive)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"

    # Guarantee at least one of each character class for practical policy compliance.
    
    pw = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+"),
    ]
    pw += [secrets.choice(alphabet) for _ in range(length - len(pw))]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def _print_entry(entry: dict, reveal: bool):
    print(f"ID:       {entry['id']}")
    print(f"Site:     {entry['site']}")
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password'] if reveal else '********'}")
    if entry.get("notes"):
        print(f"Notes:    {entry['notes']}")
    print(f"Created:  {entry['created']}")


def build_parser():
    p = argparse.ArgumentParser(prog="pm.py", description="Local encrypted password manager")
    p.add_argument("--vault", default=DEFAULT_VAULT_PATH, help="Path to vault file (default: ./vault.json)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create a new vault").set_defaults(func=cmd_init)
    sub.add_parser("add", help="Add a new entry").set_defaults(func=cmd_add)

    p_get = sub.add_parser("get", help="Show one entry by id")
    p_get.add_argument("id", type=int)
    p_get.set_defaults(func=cmd_get)

    sub.add_parser("list", help="List all entries").set_defaults(func=cmd_list)

    p_search = sub.add_parser("search", help="Search entries")
    p_search.add_argument("query")
    p_search.set_defaults(func=cmd_search)

    p_delete = sub.add_parser("delete", help="Delete an entry by id")
    p_delete.add_argument("id", type=int)
    p_delete.set_defaults(func=cmd_delete)

    p_gen = sub.add_parser("generate", help="Generate a strong password (not saved)")
    p_gen.add_argument("length", type=int, nargs="?", default=20)
    p_gen.set_defaults(func=cmd_generate)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
