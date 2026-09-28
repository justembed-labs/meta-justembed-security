"""Account/login credential hygiene: no blank passwords, no password SSH."""

# Password-field values that mean "locked, no password login possible" --
# not a default/blank credential.
LOCKED_HASH_MARKERS = ("!", "*")


def check_no_default_credentials(rootfs):
    """Every /etc/shadow account either has a real hash or is locked.
    A blank password field means the account needs no password at all."""
    shadow = rootfs / "etc" / "shadow"
    if not shadow.is_file():
        return {"status": "pass", "detail": "no /etc/shadow in rootfs"}

    blank = []
    for line in shadow.read_text(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        user, pwhash = fields[0], fields[1]
        if pwhash == "":
            blank.append(user)
    if blank:
        return {
            "status": "fail",
            "detail": f"blank password field for: {', '.join(blank)}",
        }
    return {"status": "pass", "detail": "no blank password fields"}


def check_key_only_ssh(rootfs):
    """sshd_config must explicitly disable password auth and
    unrestricted root login, if sshd is shipped at all."""
    sshd_config = rootfs / "etc" / "ssh" / "sshd_config"
    if not sshd_config.is_file():
        return {"status": "pass", "detail": "no sshd_config in rootfs (no sshd shipped)"}

    directives = {}
    for line in sshd_config.read_text(errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, val = parts[0], parts[1].strip()
            # sshd_config takes the first occurrence of a directive.
            directives.setdefault(key, val)

    problems = []
    pw_auth = directives.get("PasswordAuthentication")
    if pw_auth != "no":
        problems.append(
            f"PasswordAuthentication is {pw_auth!r}, must be explicitly 'no'"
        )
    root_login = directives.get("PermitRootLogin")
    if root_login not in ("no", "prohibit-password"):
        problems.append(
            f"PermitRootLogin is {root_login!r}, must be 'no' or 'prohibit-password'"
        )

    if problems:
        return {"status": "fail", "detail": "; ".join(problems)}
    return {"status": "pass", "detail": "PasswordAuthentication no, PermitRootLogin restricted"}
