import re


def validate_and_normalize_domain(url: str) -> str:
    url = url.strip()
    url = url.replace("http://", "https://")

    if url.startswith("https://"):
        domain = url[len("https://") :]
    else:
        domain = url

    # Remove any trailing slash or path elements
    domain = domain.split("/")[0]

    pattern = re.compile(r"^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$")

    if not pattern.match(domain):
        raise ValueError("Invalid domain or TLD format.")

    return domain
