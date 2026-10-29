"""IOS XE configuration comparison that tolerates release-driven re-rendering.

A new IOS XE release renders the same configuration differently: sections move, system
generated policies change, defaults appear and some commands are re-spelled. A text diff
flags every upgrade. Both configurations are instead canonicalized the same way and
compared as a tree. Child order matters only in sections where it is semantic (access
lists, policy maps); everything else is compared as a set. Rewrite rules map old and new
spellings to one form and ignore rules drop system-generated lines on both sides. What is
left is reported as added or removed lines, each with its parent path.
"""

import re
from collections import Counter
from difflib import SequenceMatcher

# IOS prints only metadata above the `version` line, and it differs between running and
# startup configuration and across reboots: byte counts, `service compress-config`,
# change and NVRAM timestamps. These patterns are the fallback for output with no version.
HEADER = re.compile(
    r"^(Building configuration|Current configuration|Using \d+|Uncompressed configuration"
    r"|! Last configuration change|! NVRAM config|! No configuration change"
    r"|version \d|ntp clock-period )"
)
# Running configuration prints each certificate's DER dump; startup configuration names the
# NVRAM file that holds it. Compare certificate chains by identity, not representation.
CERTIFICATE_REFERENCE = re.compile(r"^(\s*certificate(?:\s+(?:self-signed|ca))?\s+\S+)\s+nvram:\S+\s*$")
CERTIFICATE_BODY = re.compile(r"^\s+(?:[0-9A-Fa-f]{2,8}(?:\s+[0-9A-Fa-f]{2,8})*|quit)\s*$")
BOOT = re.compile(r"^(?:(?:no )?boot (?:system|manual)(?: |$)|boot-(?:start|end)-marker$)")
BANNER = re.compile(r"^banner (\S+) (\^C|\S)(.*)$")
NUMBERED_ACL = re.compile(r"^access-list (\d+) (.+)$")
NUMBERED_HEADER = re.compile(r"^ip access-list (?:standard|extended) \d+$")


def normalized(text, boot=False):
    """Exact configuration text without metadata, for same-release comparisons and hashes."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.match(r"^version \d", line):
            lines = lines[index + 1 :]
            break
    kept, chain = [], False
    for line in lines:
        if HEADER.match(line) or not line.strip() or (boot and BOOT.match(line)):
            continue
        if not line[0].isspace():
            chain = line.startswith("crypto pki certificate chain ")
        elif chain:
            if CERTIFICATE_BODY.match(line):
                continue
            line = CERTIFICATE_REFERENCE.sub(r"\1", line)
        kept.append(line.rstrip())
    return "\n".join(kept)


def boot_lines(text):
    return re.findall(r"(?m)^(?:no )?boot (?:system|manual).*$", text)


class Rule:
    def __init__(self, name, line, parent=None, replace=None):
        self.name, self.replace = name, replace
        self.line = re.compile(line)
        self.parent = re.compile(parent) if parent else None

    def applies(self, text, parent):
        if self.parent and (parent is None or not self.parent.search(parent)):
            return False
        return bool(self.line.search(text))


# Lines the switch writes or rewrites itself. Each is reported by name when it hides a
# difference, so an operator can see what was tolerated.
BUILTIN_REWRITES = (
    # `ip domain-name`, `ip domain-lookup` and `ip domain-list` became `ip domain ...`.
    ("ip-domain-spelling", r"^(no )?ip domain-(name|lookup|list)\b", None, r"\1ip domain \2"),
    # Named access lists render with or without sequence numbers; order is still compared.
    ("acl-sequence-numbers", r"^\d+ (?=\S)", r"^(?:ip|mac) access-list ", ""),
    (
        "ipv6-acl-sequence-numbers",
        r"^(?:sequence \d+ )?(.*?)(?: sequence \d+)?$",
        r"^ipv6 access-list ",
        r"\1",
    ),
)
BUILTIN_IGNORES = (
    ("control-plane-policy-classes", r"^class-map (?:match-any |match-all )?system-cpp-"),
    ("control-plane-policy", r"^policy-map system-cpp-"),
    ("smart-licensing-trustpoint", r"^crypto pki (?:trustpoint|certificate chain) SLA-TrustPoint$"),
    ("smart-licensing-call-home", r"^(?:service call-home|call-home)$"),
    ("smart-licensing-transport", r"^license smart "),
    ("default-service-templates", r"^service-template (?:webauth-global-inactive|DEFAULT_[A-Z_]+)$"),
    ("app-hosting-interfaces", r"^interface AppGigabitEthernet\d"),
    ("memory-low-watermark", r"^memory free low-watermark processor \d+$"),
)
# Sections whose child order is semantic.
BUILTIN_ORDERED = (r"^(?:ip|ipv6|mac) access-list ", r"^policy-map ")


def rules(policy):
    builtin = policy is None or policy.builtin_rules
    rewrites = [Rule(*r) for r in BUILTIN_REWRITES] if builtin else []
    ignores = [Rule(name, line) for name, line in BUILTIN_IGNORES] if builtin else []
    ordered = list(BUILTIN_ORDERED) if builtin else []
    if policy is not None:
        rewrites += [Rule(r.name or "rewrite:" + r.line, r.line, r.parent, r.replace) for r in policy.rewrite]
        ignores += [Rule(r.name or "ignore:" + r.line, r.line, r.parent) for r in policy.ignore]
        ordered += policy.ordered_sections
    return rewrites, ignores, [re.compile(p) for p in ordered]


def logical_lines(text):
    """(indent, text) pairs: comments dropped, whitespace collapsed, banners and numbered ACLs folded."""
    lines = normalized(text, boot=True).splitlines()
    out, index, acl_header = [], 0, None
    while index < len(lines):
        raw = lines[index]
        index += 1
        stripped = raw.strip()
        if stripped.startswith("!") or stripped == "end":
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        banner = BANNER.match(raw) if not indent else None
        if banner:
            kind, delimiter, rest = banner.groups()
            body = [rest]
            while delimiter not in body[-1] and index < len(lines):
                body.append(lines[index])
                index += 1
            out.append((0, "banner " + kind + " " + "\\n".join(body).split(delimiter)[0].strip()))
            acl_header = None
            continue
        acl = NUMBERED_ACL.match(stripped) if not indent else None
        number = int(acl[1]) if acl else 0
        # `access-list 10 permit ...` and `ip access-list standard 10` are the same list.
        kind = (
            "standard"
            if number and (number < 100 or 1300 <= number < 2000)
            else "extended"
            if number and (number < 200 or 2000 <= number < 2700)
            else None
        )
        if kind:
            header = f"ip access-list {kind} {number}"
            if header != acl_header:
                out.append((0, header))
                acl_header = header
            out.append((1, " ".join(acl[2].split())))
            continue
        if not indent:
            acl_header = None
        out.append((indent, " ".join(stripped.split())))
    return out


def tree(text):
    root = {"text": None, "children": []}
    stack = [(-1, root)]
    for indent, line in logical_lines(text):
        while stack[-1][0] >= indent:
            stack.pop()
        node = {"text": line, "children": []}
        stack[-1][1]["children"].append(node)
        stack.append((indent, node))
    return root


def merge_numbered(root):
    """Join numbered ACL sections split by other lines; numbered entries are one list."""
    seen, kept = {}, []
    for node in root["children"]:
        if NUMBERED_HEADER.match(node["text"] or "") and node["text"] in seen:
            seen[node["text"]]["children"] += node["children"]
            continue
        seen.setdefault(node["text"], node)
        kept.append(node)
    root["children"] = kept
    return root


def flatten(node, path):
    lines = [path + (node["text"],)]
    for child in node["children"]:
        lines += flatten(child, path + (node["text"],))
    return lines


class Canonical:
    """One configuration with the rules applied, and what each rule matched."""

    def __init__(self, text, rewrites, ignores):
        self.rewrites, self.ignores = rewrites, ignores
        self.rewritten, self.ignored = {}, {}
        self.root = self.apply(merge_numbered(tree(text)), None)

    def apply(self, node, parent):
        children = []
        for child in node["children"]:
            text = child["text"]
            for rule in self.rewrites:
                if rule.applies(text, parent):
                    new = rule.line.sub(rule.replace, text, count=1).strip()
                    if new != text:
                        self.rewritten.setdefault(rule.name, Counter())[text] += 1
                        text = new
            hit = next((rule for rule in self.ignores if rule.applies(text, parent)), None)
            if hit:
                self.ignored.setdefault(hit.name, Counter()).update(
                    " > ".join(p for p in line if p) for line in flatten({**child, "text": text}, ())
                )
                continue
            children.append(self.apply({"text": text, "children": child["children"]}, text))
        return {"text": node["text"], "children": children}


def compare(before, after, policy=None, limit=500):
    """Differences between two configurations after canonicalization.

    Returns added and removed lines (parent path joined with ` > `), the number of sections
    whose order alone changed, and the rules that hid a difference.
    """
    rewrites, ignores, ordered = rules(policy)
    old, new = Canonical(before, rewrites, ignores), Canonical(after, rewrites, ignores)
    added, removed, reordered = [], [], []

    def subtree(node, path):
        return [" > ".join(line) for line in flatten(node, path)]

    def walk(a, b, path, ordered_children):
        if ordered_children:
            matcher = SequenceMatcher(a=[n["text"] for n in a], b=[n["text"] for n in b], autojunk=False)
            for op, i1, i2, j1, j2 in matcher.get_opcodes():
                if op == "equal":
                    for x, y in zip(a[i1:i2], b[j1:j2]):
                        pair(x, y, path)
                    continue
                for node in a[i1:i2]:
                    removed.extend(subtree(node, path))
                for node in b[j1:j2]:
                    added.extend(subtree(node, path))
            return
        remaining = {}
        for node in b:
            remaining.setdefault(node["text"], []).append(node)
        matched = []
        for node in a:
            candidates = remaining.get(node["text"])
            if candidates:
                other = candidates.pop(0)
                matched.append((node, other))
                pair(node, other, path)
            else:
                removed.extend(subtree(node, path))
        for nodes in remaining.values():
            for node in nodes:
                added.extend(subtree(node, path))
        partners = {id(y) for _, y in matched}
        if [x["text"] for x, _ in matched] != [n["text"] for n in b if id(n) in partners]:
            reordered.append(" > ".join(path) or "(top level)")

    def pair(x, y, path):
        walk(
            x["children"],
            y["children"],
            path + (x["text"],),
            any(p.search(x["text"]) for p in ordered),
        )

    walk(old.root["children"], new.root["children"], (), False)
    tolerated = []
    for name in sorted(set(old.rewritten) | set(new.rewritten)):
        # Original spellings hidden by a rewrite, compared side by side.
        a, b = old.rewritten.get(name, Counter()), new.rewritten.get(name, Counter())
        if a != b:
            tolerated.append(
                {
                    "rule": name,
                    "kind": "rewrite",
                    "before": sum(a.values()),
                    "after": sum(b.values()),
                    "lines_hidden": sum(((a - b) + (b - a)).values()),
                }
            )
    for name in sorted(set(old.ignored) | set(new.ignored)):
        a, b = old.ignored.get(name, Counter()), new.ignored.get(name, Counter())
        if a != b:
            tolerated.append(
                {
                    "rule": name,
                    "kind": "ignore",
                    "before": sum(a.values()),
                    "after": sum(b.values()),
                    "lines_hidden": sum(((a - b) + (b - a)).values()),
                }
            )
    if reordered:
        tolerated.append(
            {"rule": "section-order", "kind": "order", "sections": len(reordered), "paths": reordered[:20]}
        )
    return {
        "equivalent": not added and not removed,
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added[:limit],
        "removed": removed[:limit],
        "tolerated": tolerated,
    }
