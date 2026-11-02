"""What's running and what it exposes: enabled services, and whether an
exposed one (swupdate's webserver) is actually protected."""


def check_minimal_service_surface(rootfs, allowed):
    """Every systemd unit enabled in the rootfs (a symlink under
    etc/systemd/system/*.wants/) must be in the caller-supplied
    allowlist. No allowlist means every enabled unit is unlisted --
    fails loud rather than silently passing, so JE_HYGIENE_ALLOWED_SERVICES
    has to be set deliberately, not left to a default that means
    nothing."""
    systemd_dir = rootfs / "etc" / "systemd" / "system"
    if not systemd_dir.is_dir():
        return {"status": "pass", "detail": "no etc/systemd/system in rootfs (not a systemd image)"}

    enabled = set()
    for wants_dir in sorted(systemd_dir.glob("*.wants")):
        if not wants_dir.is_dir():
            continue
        for entry in wants_dir.iterdir():
            if entry.is_symlink() or entry.is_file():
                enabled.add(entry.name)

    if not enabled:
        return {"status": "pass", "detail": "no enabled units found"}

    unlisted = sorted(enabled - allowed)
    if unlisted:
        return {
            "status": "fail",
            "detail": f"enabled units not in allowlist: {', '.join(unlisted)}",
        }
    return {"status": "pass", "detail": f"{len(enabled)} enabled unit(s), all allowlisted"}


def _swupdate_conf_d_files(rootfs):
    """swupdate.sh sources etc/swupdate/conf.d/<name> in preference to
    the matching usr/lib/swupdate/conf.d/<name>, for each name present
    in either -- same precedence, replicated here for the check."""
    by_name = {}
    for base in ("usr/lib/swupdate/conf.d", "usr/lib64/swupdate/conf.d"):
        d = rootfs / base
        if d.is_dir():
            for f in d.iterdir():
                if f.is_file():
                    by_name.setdefault(f.name, f)
    etc_d = rootfs / "etc" / "swupdate" / "conf.d"
    if etc_d.is_dir():
        for f in etc_d.iterdir():
            if f.is_file():
                by_name[f.name] = f  # etc/ wins over usr/lib/
    return [by_name[name] for name in sorted(by_name)]


def check_swupdate_webserver_protected(rootfs):
    """swupdate's own webserver mode (SWUPDATE_WEBSERVER_ARGS, see
    swupdate.sh) accepts a pushed update over HTTP with no channel
    protection unless the conf.d file also enables SSL (-s/--ssl) or
    HTTP auth (--global-auth-file). Signing (-k) alone doesn't cover
    this: a captured, still-validly-signed old bundle can still be
    replayed over an unprotected channel."""
    files = _swupdate_conf_d_files(rootfs)
    if not files:
        return {"status": "pass", "detail": "no swupdate conf.d in rootfs (swupdate not configured)"}

    webserver_args = ""
    for f in files:
        text = f.read_text(errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("SWUPDATE_WEBSERVER_ARGS="):
                # Later conf.d files (sorted) override earlier ones,
                # same as swupdate.sh re-sourcing each in turn.
                webserver_args = line.split("=", 1)[1].strip().strip('"\'')

    if not webserver_args:
        return {"status": "pass", "detail": "SWUPDATE_WEBSERVER_ARGS unset/empty, webserver mode not active"}

    protected = ("--ssl" in webserver_args or " -s " in f" {webserver_args} "
                 or "--global-auth-file" in webserver_args)
    if protected:
        return {"status": "pass", "detail": f"webserver active with SSL or auth: {webserver_args!r}"}
    return {
        "status": "fail",
        "detail": (
            f"webserver active with no --ssl/-s or --global-auth-file: {webserver_args!r} "
            "-- update-push channel is plaintext, unauthenticated"
        ),
    }
