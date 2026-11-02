"""Rootfs persistence/mutability."""


def check_read_only_rootfs(rootfs):
    """Report-only, permanently -- feasibility is per-target (storage
    wear, whether the app writes to disk at runtime), never a
    universal hard requirement. Reads etc/fstab's root entry, the same
    place OE's read-only-rootfs IMAGE_FEATURE actually changes."""
    fstab = rootfs / "etc" / "fstab"
    if not fstab.is_file():
        return {"status": "report", "detail": "no etc/fstab in rootfs, can't determine"}

    for line in fstab.read_text(errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 4:
            continue
        mount_point, options = fields[1], fields[3]
        if mount_point == "/":
            opts = options.split(",")
            if "ro" in opts:
                return {"status": "report", "detail": "root mounted read-only (fstab: ro)"}
            return {"status": "report", "detail": f"root mounted read-write (fstab options: {options})"}

    return {"status": "report", "detail": "no root (/) entry in fstab, can't determine"}
