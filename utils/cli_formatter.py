from utils.colors import critical, error, info, success, warning


def format_cli_output(text, level="info"):
    level = (level or "info").lower()

    if level == "success":
        return success(text)
    if level == "warning":
        return warning(text)
    if level == "error":
        return error(text)
    if level == "critical":
        return critical(text)
    return info(text)
