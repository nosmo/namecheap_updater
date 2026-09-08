#!/usr/bin/env python3
"""Update a TXT record on a Namecheap-hosted domain.

Namecheap has no way to update a single record. setHosts allows you to
update existing records wholesale. Get all hosts, update the record
and then write them back.

This is obviously a bit scary. Attempt to guard this a few ways:
* Archive the current zone pre-write
* Refuse to write records we don't understand
* Diff against created records to see if we messed anything up

Credentials from the environment:

    NAMECHEAP_API_USER    API user (usually namecheap username)
    NAMECHEAP_API_KEY     API key
    NAMECHEAP_USERNAME    account username (defaults to NAMECHEAP_API_USER)
    NAMECHEAP_CLIENT_IP   the whitelisted IP the request comes from
    NAMECHEAP_BACKUP_DIR  where to archive zone backups (default:
                          ./namecheap-backups)

Exit 0 on success.
Exit 2 on a failure to validate a commited write
Exit 1 on everything else

Examples:

    # set (replace) the _acme-challenge TXT record
    namecheap_txt.py -d example.com -n _acme-challenge -v "token123"

    # add a second TXT value alongside any existing ones
    namecheap_txt.py -d example.com -n @ -v "v=spf1 -all" --append

    # remove all TXT records at that name
    namecheap_txt.py -d example.com -n _acme-challenge --delete

    # show what would be sent without sending it
    namecheap_txt.py -d example.com -n @ -v "hello" --dry-run

Yeah this thing could update all kinds of records but I don't want to
do that, I just want to do TXT records.

"""

import argparse
import os
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree

PROD_URL = "https://api.namecheap.com/xml.response"
SANDBOX_URL = "https://api.sandbox.namecheap.com/xml.response"

DEFAULT_TTL = 1800
DEFAULT_BACKUP_DIR = "namecheap-backups"

# setHosts is documented as supporting this list of records - notably
# SRV is missing, so we will panic out if we encounter it or another
# type of unspported record.
SETHOSTS_TYPES = frozenset(
    [
        "A",
        "AAAA",
        "ALIAS",
        "CAA",
        "CNAME",
        "MX",
        "MXE",
        "NS",
        "TXT",
        "URL",
        "URL301",
        "FRAME",
    ]
)


class NamecheapError(Exception):
    pass


class Namecheap:
    def __init__(self, api_user, api_key, username, client_ip, sandbox=False):
        self.url = SANDBOX_URL if sandbox else PROD_URL
        self.last_raw = None
        self.globals = {
            "ApiUser": api_user,
            "ApiKey": api_key,
            "UserName": username,
            "ClientIp": client_ip,
        }

    def call(self, command, params):
        """POST a command and return the CommandResponse element.

        Saves a raw unprocessed result in self.last_raw for reuse
        """
        body = dict(self.globals, Command=command, **params)
        data = urllib.parse.urlencode(body).encode()
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
        self.last_raw = raw

        root = xml.etree.ElementTree.fromstring(raw)
        # The namespace URI differs between commands (http:// vs https://) and
        # between sandbox and production, so match on local names instead.
        if root.get("Status") != "OK":
            errors = [
                "%s: %s" % (e.get("Number"), (e.text or "").strip())
                for e in root.iter()
                if strip_ns(e.tag) == "Error"
            ]
            raise NamecheapError(
                "%s failed: %s"
                % (command, "; ".join(errors) or raw.decode(errors="replace"))
            )
        for child in root:
            if strip_ns(child.tag) == "CommandResponse":
                return child
        raise NamecheapError("no CommandResponse in reply to %s" % command)


def strip_ns(tag):
    # strip namespace from a tag
    return tag.rsplit("}", 1)[-1]


def split_domain(domain):
    """example.co.uk -> ('example', 'co.uk')."""
    labels = domain.strip(".").split(".")
    if len(labels) < 2:
        raise ValueError("not a domain name: %r" % domain)
    return labels[0], ".".join(labels[1:])


def get_hosts(client, sld, tld):
    """Return (records, email_type, raw_xml).

    Records are dicts of the getHosts fields; raw_xml is the unparsed reply,
    kept so it can be archived before a rewrite.
    """
    resp = client.call("namecheap.domains.dns.getHosts", {"SLD": sld, "TLD": tld})
    result = next(e for e in resp if strip_ns(e.tag) == "DomainDNSGetHostsResult")
    if result.get("IsUsingOurDNS") == "false":
        raise NamecheapError(
            "%s.%s is not using Namecheap DNS; host records cannot be edited"
            % (sld, tld)
        )
    records = [
        {
            "Name": h.get("Name"),
            "Type": h.get("Type"),
            "Address": h.get("Address"),
            "MXPref": h.get("MXPref") or "10",
            "TTL": h.get("TTL") or str(DEFAULT_TTL),
        }
        for h in result
        if strip_ns(h.tag) == "host"
    ]
    # EmailType is preserved so that writing records back does not reset the
    # domain's mail configuration. Not in the setHosts docs' parameter table,
    # but getHosts returns it and setHosts accepts it.
    return records, result.get("EmailType"), client.last_raw


def set_hosts(client, sld, tld, records, email_type=None):
    params = {"SLD": sld, "TLD": tld}
    for i, rec in enumerate(records, start=1):
        params["HostName%d" % i] = rec["Name"]
        params["RecordType%d" % i] = rec["Type"]
        params["Address%d" % i] = rec["Address"]
        params["TTL%d" % i] = rec["TTL"]
        if rec["Type"] in ("MX", "MXE"):
            params["MXPref%d" % i] = rec["MXPref"]
    if email_type:
        params["EmailType"] = email_type

    resp = client.call("namecheap.domains.dns.setHosts", params)
    result = next(e for e in resp if strip_ns(e.tag) == "DomainDNSSetHostsResult")
    if result.get("IsSuccess") != "true":
        raise NamecheapError("setHosts reported IsSuccess=%r" % result.get("IsSuccess"))


def unwritable_types(records):
    """Types present in the zone that setHosts cannot express."""
    return sorted({r["Type"] for r in records if r["Type"] not in SETHOSTS_TYPES})


def write_backup(raw, sld, tld, backup_dir):
    """Archive the getHosts reply byte-for-byte. Returns the path written."""
    if raw is None:
        raise NamecheapError("no getHosts response to back up")
    os.makedirs(backup_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = os.path.join(backup_dir, "%s.%s-%s.xml" % (sld, tld, stamp))
    # Exclusive create: never clobber an existing backup, even on a same-second
    # second run.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    for attempt in range(100):
        candidate = path if attempt == 0 else "%s.%d" % (path, attempt)
        try:
            fd = os.open(candidate, flags, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        return candidate
    raise NamecheapError("could not create a backup file in %s" % backup_dir)


def diff_records(sent, found):
    """Compare what we sent against what getHosts reports afterwards.

    Returns (missing, unexpected, changed). Address/TTL are compared per
    (Name, Type, Address) identity; a record present with a different TTL shows
    up in `changed` rather than as a loss, since the API may normalise values.
    """

    def ident(r):
        return (r["Name"], r["Type"], r["Address"])

    sent_by_ident = {ident(r): r for r in sent}
    found_by_ident = {ident(r): r for r in found}

    missing = [sent_by_ident[k] for k in sent_by_ident if k not in found_by_ident]
    unexpected = [found_by_ident[k] for k in found_by_ident if k not in sent_by_ident]
    changed = [
        (sent_by_ident[k], found_by_ident[k])
        for k in sent_by_ident
        if k in found_by_ident and sent_by_ident[k]["TTL"] != found_by_ident[k]["TTL"]
    ]
    return missing, unexpected, changed


def describe(rec):
    return "%s %s %s (TTL %s)" % (rec["Name"], rec["Type"], rec["Address"], rec["TTL"])


def apply_change(records, name, value, ttl, append, delete):
    """Return a new record list with the TXT change applied."""
    kept = [
        r
        for r in records
        if not (
            r["Type"] == "TXT"
            and r["Name"] == name
            and (not append or r["Address"] == value)
        )
    ]
    if delete:
        return kept
    return kept + [
        {"Name": name, "Type": "TXT", "Address": value, "MXPref": "10", "TTL": str(ttl)}
    ]


def update(client, sld, tld, args):
    """The read-modify-write itself"""
    existing, email_type, raw = get_hosts(client, sld, tld)
    print("%d existing host record(s)" % len(existing), file=sys.stderr)

    # Any rewrite of this zone would drop these, so refuse before touching it.
    unwritable = unwritable_types(existing)
    if unwritable:
        message = (
            "%s.%s holds record type(s) setHosts cannot write back: %s\n"
            "Rewriting the zone would delete them. Move or remove those "
            "records, or pass --allow-unwritable-types to accept the loss."
            % (sld, tld, ", ".join(unwritable))
        )
        if not args.allow_unwritable_types:
            sys.exit(message)
        print("WARNING: %s" % message, file=sys.stderr)

    updated = apply_change(
        existing, args.name, args.value, args.ttl, args.append, args.delete
    )
    if sorted([ sorted(record.items()) for record in updated ]) == sorted([ sorted(record.items()) for record in existing ]):
        print("nothing to change", file=sys.stderr)
        return 0

    for rec in updated:
        print(
            "  %-30s %-6s %-6s %s"
            % (rec["Name"], rec["Type"], rec["TTL"], rec["Address"]),
            file=sys.stderr,
        )
    if args.dry_run:
        print("dry run: not sending setHosts", file=sys.stderr)
        return 0

    # Guard against wiping a zone if getHosts came back suspiciously empty.
    if existing and not updated:
        sys.exit("refusing to send an empty record set")

    if args.no_backup:
        print("WARNING: proceeding without a zone backup", file=sys.stderr)
    else:
        # Fail closed: no archive of the current zone, no rewrite.
        path = write_backup(raw, sld, tld, args.backup_dir)
        print("backed up current zone to %s" % path, file=sys.stderr)

    set_hosts(client, sld, tld, updated, email_type)
    print("wrote %d record(s) to %s.%s" % (len(updated), sld, tld), file=sys.stderr)

    if args.no_verify:
        return 0
    return verify(client, sld, tld, updated)


def verify(client, sld, tld, sent):
    """Re-read the zone and report anything that did not land as sent."""
    found, _, _ = get_hosts(client, sld, tld)
    missing, unexpected, changed = diff_records(sent, found)

    for rec in missing:
        print("MISSING after write: %s" % describe(rec), file=sys.stderr)
    for rec in unexpected:
        print("UNEXPECTED after write: %s" % describe(rec), file=sys.stderr)
    for was, now in changed:
        print(
            "TTL changed by the API: %s %s %s -> %s"
            % (was["Name"], was["Type"], was["TTL"], now["TTL"]),
            file=sys.stderr,
        )

    if missing or unexpected:
        print(
            "verification FAILED: the zone does not match what was sent; "
            "compare against the backup",
            file=sys.stderr,
        )
        return 2
    print("verified: %d record(s) match what was sent" % len(sent), file=sys.stderr)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser("Update a TXT record on a Namecheap-hosted domain")
    p.add_argument("-d", "--domain", required=True, help="e.g. example.com")
    p.add_argument("-n", "--name", required=True, help="record name; '@' for the apex")
    p.add_argument("-v", "--value", help="TXT value (required unless --delete)")
    p.add_argument(
        "--ttl",
        type=int,
        default=DEFAULT_TTL,
        help="60-60000, default %d" % DEFAULT_TTL,
    )
    p.add_argument(
        "--append",
        action="store_true",
        help="keep other TXT records at this name instead of replacing them",
    )
    p.add_argument(
        "--delete", action="store_true", help="remove TXT records at this name"
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="print the resulting record set without calling setHosts",
    )
    p.add_argument("--sandbox", action="store_true", help="use the sandbox API")
    p.add_argument(
        "--backup-dir",
        default=os.environ.get("NAMECHEAP_BACKUP_DIR", DEFAULT_BACKUP_DIR),
        help="where to archive the pre-write getHosts XML (default: %s)"
        % DEFAULT_BACKUP_DIR,
    )
    p.add_argument(
        "--no-backup",
        action="store_true",
        help="skip the pre-write zone backup (not recommended)",
    )
    p.add_argument(
        "--no-verify",
        action="store_true",
        help="skip the post-write getHosts check",
    )
    p.add_argument(
        "--allow-unwritable-types",
        action="store_true",
        help="proceed even if the zone holds record types setHosts cannot "
        "express; those records WILL be lost",
    )
    args = p.parse_args(argv)

    if args.delete and args.value:
        p.error("give either --value or --delete")
    if not 60 <= args.ttl <= 60000:
        p.error("--ttl must be between 60 and 60000")

    api_user = os.environ.get("NAMECHEAP_API_USER")
    api_key = os.environ.get("NAMECHEAP_API_KEY")

    # TODO hook into something like ifconfig.me to get local IP?
    client_ip = os.environ.get("NAMECHEAP_CLIENT_IP")
    if not all([api_user, api_key, client_ip]):
        sys.exit(
            "API user, API key and API client IP environment variables must be set"
        )

    sld, tld = split_domain(args.domain)
    client = Namecheap(
        api_user,
        api_key,
        os.environ.get("NAMECHEAP_USERNAME") or api_user,
        client_ip,
        sandbox=args.sandbox,
    )

    return update(client, sld, tld, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (NamecheapError, ValueError) as exc:
        sys.exit(str(exc))
