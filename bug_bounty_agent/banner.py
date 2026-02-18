"""Visual identity for the bug bounty agent."""

from __future__ import annotations

import subprocess

RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[38;5;196m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[38;5;220m"
WHITE = "\033[38;5;255m"
CYAN = "\033[38;5;51m"
GRAY = "\033[38;5;245m"

def _figlet(text: str, font: str = "standard") -> list[str]:
    out = subprocess.run(
        ["figlet", "-f", font, text],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.rstrip("\n")
    return out.splitlines()

def render_banner() -> str:
    flames = f"{RED}^^{ORANGE}( ){YELLOW}( ){ORANGE}( ){RED}^^{RESET}"
    top = f"{flames}  {BOLD}{WHITE}[ THREAT OPS ]{RESET}  {flames}"

    bug_bounty = _figlet("BUG BOUNTY", "standard")
    agent = _figlet("AGENT", "standard")

    lines: list[str] = [top]
    lines.extend(f"{BOLD}{RED}{line}{RESET}" for line in bug_bounty)
    lines.extend(f"{BOLD}{YELLOW}{line}{RESET}" for line in agent)
    lines.append(f"{GRAY}{'-' * 56}{RESET}")
    lines.append(f"{CYAN}TRIGGER -> ./bug_bounty{RESET}")
    return "\n".join(lines)
