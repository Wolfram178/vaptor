from colorama import Fore, Style, init

init(autoreset=True)


def success(text):
    return Fore.GREEN + text + Style.RESET_ALL


def info(text):
    return Fore.CYAN + text + Style.RESET_ALL


def warning(text):
    return Fore.YELLOW + text + Style.RESET_ALL


def error(text):
    return Fore.RED + text + Style.RESET_ALL


def critical(text):
    return Fore.RED + Style.BRIGHT + text + Style.RESET_ALL


# ----------------------------
# Severity-based coloring
# ----------------------------
def severity_color(text, severity):
    if not severity:
        return text

    sev = str(severity).lower()

    if sev in ["critical", "4"]:
        return Fore.RED + Style.BRIGHT + text + Style.RESET_ALL
    elif sev in ["high", "3"]:
        return Fore.RED + text + Style.RESET_ALL
    elif sev in ["medium", "2"]:
        return Fore.YELLOW + text + Style.RESET_ALL
    elif sev in ["low", "1"]:
        return Fore.GREEN + text + Style.RESET_ALL
    else:
        return Fore.CYAN + text + Style.RESET_ALL