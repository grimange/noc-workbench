# Fixed-source, transient read-only protocol. Also installed as a reviewed gateway.
# Never prints logger configuration, raw diagnostics or arbitrary files.
import base64
import hashlib
import json
import os
import re
import stat
import sys

LIMIT = 24576
SOURCES = ("security", "security_log", "messages", "full")


def output(status, **fields):
    print(json.dumps(dict(status=status, **fields), separators=(",", ":")))


def opened(path, directory=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("not_regular")
    return fd


def read(request, config="/etc/asterisk/logger.conf", logdir="/var/log/asterisk"):
    # config/logdir are test injection points, never taken from the protocol.
    if not isinstance(request, dict) or set(request) - set(SOURCES):
        raise ValueError("request")
    for c in request.values():
        if not isinstance(c, dict) or set(c) != {"identity", "offset", "generation", "anchor", "gap", "discard"}:
            raise ValueError("cursor")
        if not re.fullmatch(r"[0-9]{1,20}:[0-9]{1,20}|", c["identity"]):
            raise ValueError("identity")
        if any(type(c[k]) is not int or not 0 <= c[k] <= 2**53 for k in ("offset", "generation")):
            raise ValueError("position")
        if not re.fullmatch(r"[a-f0-9]{64}|", c["anchor"]) or type(c["gap"]) is not bool or type(c["discard"]) is not bool:
            raise ValueError("anchor")
    try:
        fd = opened(config)
        try:
            cfg = os.read(fd, 32769)
        finally:
            os.close(fd)
        if len(cfg) > 32768:
            return dict(status="unsupported_configuration")
    except PermissionError:
        return dict(status="permission_denied")
    except (OSError, ValueError):
        return dict(status="no_configured_source")
    configured = {}
    section = ""
    incomplete = False
    warnings_supported = False
    for line in cfg.decode("utf-8", "replace").splitlines():
        line = line.split(";", 1)[0].strip()
        if line.startswith("#"):
            incomplete = True  # Includes cannot authorize arbitrary destinations.
        if line.startswith("["):
            section = line.lower()
        if section == "[general]" and "=" in line:
            key, value = line.split("=", 1)
            if key.strip().lower() == "dateformat":
                warnings_supported = value.strip() in ("%F %T", "%F %T.%3q", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%3q")
        if section == "[logfiles]" and "=" in line:
            name, facilities = line.split("=", 1)
            name = name.strip()
            facilities = {x.strip().lower() for x in facilities.lstrip(">").split(",")}
            if name in SOURCES:
                configured[name] = facilities
            elif name != "console" and facilities & {"security", "notice", "warning"}:
                incomplete = True
    eligible = [s for s in SOURCES if "security" in configured.get(s, set())]
    eligible += [s for s in ("messages", "full") if s not in eligible and configured.get(s, set()) & {"notice", "warning"}]
    if not eligible:
        return dict(status="unsupported_configuration" if incomplete else "no_configured_source")
    try:
        directory = os.open(logdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except PermissionError:
        return dict(status="permission_denied")
    except OSError:
        return dict(status="missing_source")
    denied = False
    try:
        for source in eligible:
            try:
                fd = opened(source, directory)
            except PermissionError:
                denied = True
                continue
            except (OSError, ValueError):
                continue
            try:
                info = os.fstat(fd)
                identity = str(info.st_dev) + ":" + str(info.st_ino)
                previous = request.get(source)
                generation = previous["generation"] if previous else 1
                offset = previous["offset"] if previous else max(0, info.st_size - LIMIT)
                gap = previous["gap"] if previous else offset > 0
                skip = previous["discard"] if previous else offset > 0
                rotated = False
                if previous and previous["identity"] != identity:
                    # Drain one retained uncompressed generation, without globbing.
                    found = False
                    for suffix in (".1", ".0"):
                        try:
                            old = opened(source + suffix, directory)
                        except (OSError, ValueError):
                            continue
                        oldinfo = os.fstat(old)
                        oldid = str(oldinfo.st_dev) + ":" + str(oldinfo.st_ino)
                        if oldid == previous["identity"] and oldinfo.st_size > offset:
                            os.close(fd)
                            fd, info, identity = old, oldinfo, oldid
                            found = True
                            rotated = True
                            break
                        os.close(old)
                        if oldid == previous["identity"] and oldinfo.st_size == offset:
                            found = True
                            break
                    if not rotated:
                        generation += 1
                        offset = 0
                        skip = False
                        gap = gap or not found
                if previous and identity == previous["identity"]:
                    check = os.pread(fd, min(offset, 64), max(0, offset - 64))
                    if info.st_size < offset or (previous["anchor"] and hashlib.sha256(check).hexdigest() != previous["anchor"]):
                        generation += 1
                        offset = 0
                        skip = False
                        gap = True
                data = os.pread(fd, min(LIMIT, max(0, info.st_size - offset)), offset)
                after = os.fstat(fd)
                if after.st_size < info.st_size:
                    return dict(status="changed_during_read", source=source)
                return dict(status="read", source=source, identity=identity, generation=generation,
                            offset=offset, size=info.st_size, prefix=base64.b64encode(os.pread(fd, min(offset, 64), max(0, offset - 64))).decode("ascii"), data=base64.b64encode(data).decode("ascii"),
                            skip=skip, gap=gap, rotated=rotated, configuration_incomplete=incomplete,
                            security="security" in configured[source], warnings_supported=warnings_supported,
                            # Timezone is evidence used only for year-bearing messages timestamps.
                            timezone=__import__("time").strftime("%z"))
            finally:
                os.close(fd)
        return dict(status="permission_denied" if denied else "missing_source")
    finally:
        os.close(directory)


def main():
    if len(sys.argv) != 1:
        return output("invalid_request")
    try:
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise ValueError("request_limit")
        result = read(json.loads(raw))
        output(**result)
    except Exception:
        output("invalid_request")


if __name__ == "__main__":
    main()
