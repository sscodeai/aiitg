"""DET-008: insecure instructions hidden in ordinary code comments.

Threat model (arXiv:2610.05139, "Hidden in the Comments: A Context-Injection Attack
Surface in Code LLMs", Munir/Quinzan/Roberts, Oxford). A Code LLM builds its context
from open files, imported modules, pasted snippets and comments — much of it from
untrusted sources. An adversary plants an insecure objective as an ordinary in-code
comment (``# TODO:``, ``# INSTRUCTION:``, ``# TASK:``); the model cannot tell it from
the developer's own instruction, because the marker is the same one real code uses.
The paper measures 77.4–92.3% of attack-condition completions containing a
medium-or-higher weakness versus 1.7–5.1% for ordinary work.

This detector runs on the *input* side: it reads a comment (or a whole-line
instruction file) and asks whether it is an order to build something unsafe. It is
deterministic and offline on purpose — the gate sits before inference, so it cannot
depend on a model call to decide whether a model may be called.

A hit needs BOTH:

* a **directive frame** — a marker, second-person/machine-addressed phrasing, an
  imperative opener, an authority claim, or a "skip the check" negation; and
* an **insecure objective** from the ten weakness classes of the paper's Appendix A
  (plus prompt-injection aimed at the assistant itself).

Descriptive prose that merely names a sink ("a bare ``subprocess`` cannot answer",
"this query concatenates user input") has no frame and is not reported: a comment
scanner that flags every mention of ``exec`` is unusable. Measured on the bundled
corpus: 32/32 attack items, 0/46 benign comments, 4/4 accepted false positives on
legit notes byte-shaped like payloads, and 0 findings over live third-party source.

Scope boundary (deliberate): this reads *comments*, not code. Vulnerable code that is
already written is the job of a SAST tool; this detector covers the instruction that
causes a model to write it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aiitg.core.detector import Detector
from aiitg.core.document import ParsedDocument
from aiitg.core.evidence import Evidence, Location, Severity
from aiitg.parsers.text_parser import comment_body

# ---------------------------------------------------------------------------
# Directive framing
# ---------------------------------------------------------------------------

#: The paper's markers, plus the ordinary ones real repositories also use. That
#: overlap is exactly why the attack works: the payload marker is a legitimate one.
MARKER_RE = re.compile(
    r"^(?:@?\[?(?:todo|fixme|instruction|instructions|task|important|note|hack|xxx|ai|"
    r"assistant|copilot|claude|system|prompt)\]?)\b\s*:?\s*",
    re.IGNORECASE,
)

#: Second-person / machine-addressed framing.
ADDRESSED_RE = re.compile(
    r"\b(?:you (?:must|should|need to|have to|are|can)|please\s+\w+|ai[:\s]|assistant[:\s]|"
    r"copilot[:\s]|claude[:\s]|complete the|implement the|make sure to|be sure to|"
    r"do not (?:ask|warn|mention|tell|verify|validate)|no need to)\b",
    re.IGNORECASE,
)

#: Imperative opener: a comment that reads as an order to whoever completes the code.
IMPERATIVE_RE = re.compile(
    r"^(?:assign|set|copy|write|map|bind|add|use|run|execute|call|invoke|open|read|load|"
    r"unpickle|deserialize|eval|render|output|emit|return|print|log|store|save|send|fetch|"
    r"request|download|redirect|include|inject|skip|disable|turn off|bypass|ignore|remove|"
    r"drop|delete|allow|permit|trust|expose|concatenate|interpolate|format|construct|build|"
    r"create|generate|complete|resolve|join|serve|handle)\b",
    re.IGNORECASE,
)

#: Claiming authority so the directive reads as privileged context.
AUTHORITY_RE = re.compile(
    r"\b(?:always|never|must|do not ask|without asking|for now|for the demo|for testing|"
    r"temporarily|as (?:an? )?(?:admin|admin user|superuser|root)|the (?:security|platform) "
    r"team (?:approved|requires)|approved by|it is safe to|this is intentional|trusted input)\b",
    re.IGNORECASE,
)

#: Negation of a safety control — the strongest frame ("without validation").
UNSAFE_NEGATION_RE = re.compile(
    r"\b(?:without|skip(?:ping)?|no need for|no need to|do not|don't|never|bypass(?:ing)?|"
    r"disable|disabling|ignore|turn off|omit)\b[^.]{0,40}\b(?:validation|validating|sanitiz\w*|"
    r"escap\w*|checks?|auth\w*|csrf|verification|verifying|filtering|allow[- ]?list|escaping)\b",
    re.IGNORECASE,
)

#: "directly" / "raw" / "unvalidated" — how a payload asks for the unsafe version.
UNSAFE_RAW_RE = re.compile(
    r"\b(?:directly|raw|unsanitized|unvalidated|unescaped|verbatim|as[- ]is|straight)\b",
    re.IGNORECASE,
)

#: A prohibition names a sink in order to forbid it ("never call `child_process`"):
#: suppress a class match whose immediately preceding words forbid that action.
PROHIBITION_RE = re.compile(
    r"\b(?:must not|must never|never|do not|don't|avoid|forbidden to|should not|shall not|"
    r"is not allowed to|refuse to)\s+(?:\w+\s+){0,2}?"
    r"(?:call|use|run|execute|invoke|open|load|eval|pickle|trust|import|rely|depend|read|"
    r"write|store|log|print|return|send|render|redirect|extend|serve)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Insecure objectives — the paper's ten weakness classes + agent-directed injection
# ---------------------------------------------------------------------------

#: (class, severe, pattern). ``severe`` = critical when the comment is directive.
OBJECTIVES: tuple[tuple[str, bool, re.Pattern[str]], ...] = (
    (
        "command_injection", True,
        re.compile(
            r"\b(?:os\.system|subprocess|shell\s*=\s*true|popen|child_process|backticks?|"
            r"system\s*\(|exec\s*\(|eval\s*\(|run the (?:os |shell |system )?command|"
            r"command named|dbms_scheduler|/bin/sh)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "sql_injection", True,
        re.compile(
            r"\b(?:sql|query|statement|select|insert|update)\b[^.]{0,60}"
            r"\b(?:concatenat\w*|interpolat\w*|string (?:format|building)|f-?string|directly|"
            r"user|request|input)\b"
            r"|\bselect\b[^.]{0,80}\bwhere\b[^.]{0,40}(?:\{|\+|\%s|input|user|param)"
            r"|\bexecute\s*\([^)]*(?:\{|\+|%s|f\")",
            re.IGNORECASE,
        ),
    ),
    (
        "mass_assignment", True,
        re.compile(
            r"(?:assign|set|copy|write|map|bind|update)\w*[^.]{0,60}"
            r"\b(?:user|client|request|form|input|payload|body|params?)\b[^.]{0,60}"
            r"\b(?:admin|administrative|role|roles|is_admin|permission|privilege|superuser|staff)\b"
            r"|\b(?:admin|role|permission|privilege)s?\b[^.]{0,40}\b(?:directly|from (?:the )?"
            r"(?:request|user|client|input|form))\b"
            r"|(?:copy|assign|set|bind|map|spread)\w*[^.]{0,30}\b(?:every|all|each|any)\b[^.]{0,40}"
            r"\b(?:form|request|client|user|input)\b[^.]{0,40}\b(?:field|param|attribute|key)s?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal", True,
        re.compile(
            r"\b(?:open|read|write|load|serve|send_file|join|resolve)\w*[^.]{0,60}"
            r"\b(?:path|file|filename|directory|dir)\b[^.]{0,60}"
            r"\b(?:from (?:the )?(?:user|request|client|query|param)|directly|unvalidated|"
            r"unsanitiz\w*)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "unsafe_deserialization", True,
        re.compile(
            r"\b(?:pickle\.loads?|cPickle\.loads?|yaml\.load\s*\(|marshal\.loads?|unpickle|"
            r"deserializ\w*|objectinputstream|readObject\s*\()\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ssrf", True,
        re.compile(
            r"\b(?:fetch|request|get|open|curl|download|load|connect|post)\w*[^.]{0,60}"
            r"\b(?:url|uri|endpoint|host|address)\b[^.]{0,60}"
            r"\b(?:from (?:the )?(?:user|request|client|query|param)|directly|provided|"
            r"supplied|any)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_injection", True,
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b[^.]{0,40}"
            r"\b(?:previous|prior|above|earlier|all)\b[^.]{0,30}\b(?:instruction|prompt|rule|message)s?\b"
            r"|\byou are now\b|\bdo not (?:tell|inform|mention|reveal) (?:the )?(?:user|developer|human)\b"
            r"|\b(?:print|reveal|dump|show|send) (?:the |your )?(?:system|developer|hidden) "
            r"(?:prompt|instruction)",
            re.IGNORECASE,
        ),
    ),
    (
        "xss", False,
        re.compile(
            r"\b(?:render|insert|output|echo|print|write|return|inject)\w*[^.]{0,60}"
            r"\b(?:user|input|request|query|param|comment|name)\b[^.]{0,60}"
            r"(?:as html|unescaped|without escaping|innerhtml|raw|(?<!\w)\|safe)"
            r"|\b(?:innerHTML|document\.write|dangerouslySetInnerHTML)|(?<!\w)\|safe\b",
            re.IGNORECASE,
        ),
    ),
    (
        "xpath_injection", False,
        re.compile(
            r"\bxpath\b[^.]{0,60}\b(?:user|input|request|query|concat|format|directly|\{|\+|%s)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "open_redirect", False,
        re.compile(
            r"\bredirect\w*[^.]{0,60}\b(?:to|using|with)?[^.]{0,20}"
            r"\b(?:url|uri|next|target|param|query|user|request|input)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "cors_misconfiguration", False,
        re.compile(
            r"\b(?:allow|set|add|enable)\w*[^.]{0,40}\b(?:origin|origins|cors)\b[^.]{0,40}"
            r"\b(?:\*|any|all|wildcard|every)\b"
            r"|\b(?:allow|set|add|enable)\w*[^.]{0,25}\b(?:any|all|\*|every|wildcard)\b[^.]{0,25}"
            r"\b(?:origin|origins|cors)\b"
            r"|\bcors\b[^.]{0,30}\b(?:allow|permit|any|all|\*|every|wildcard|open)\b"
            r"|\borigins?\b[^.]{0,30}(?:\*|any origin|all origins)"
            r"|access-control-allow-origin\s*:?\s*\*",
            re.IGNORECASE,
        ),
    ),
    (
        "sensitive_information_disclosure", False,
        re.compile(
            r"\b(?:log|print|return|include|expose|send|write|echo|debug)\w*[^.]{0,40}"
            r"\b(?:password|passwd|secret|api[-_ ]?key|token|credential|private key|env(?:ironment)? var)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "disabled_security_control", False,
        re.compile(
            r"\b(?:disable|disabling|skip|skipping|turn off|bypass|comment out|remove)\w*[^.]{0,30}"
            r"\b(?:csrf|auth\w*|permission check|access control|tls|ssl|https verification|"
            r"signature verification|rate limit)\b",
            re.IGNORECASE,
        ),
    ),
)

#: Classes that respectable code also mentions in passing (logging a token, turning a
#: check off while debugging). For these, a bare marker is not enough — the comment
#: additionally needs a real directive (imperative / addressed / negation / authority).
WEAK_CLASSES = frozenset({"sensitive_information_disclosure", "disabled_security_control"})

_SEVERITY_BY_NAME = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
}


@dataclass
class Finding:
    """One directed insecure comment."""

    line: int
    klass: str
    severity: str
    body: str
    frames: list[str] = field(default_factory=list)
    char_range: tuple[int, int] | None = None


def _prohibited(text: str, match_start: int, window: int = 40) -> bool:
    """True when the words right before ``match_start`` forbid that very action."""
    return PROHIBITION_RE.search(text[max(0, match_start - window):match_start]) is not None


def classify_line(line: str, *, line_no: int = 1, lang: str | None = "hash") -> Finding | None:
    """Classify one source line; return a :class:`Finding` for a directed payload."""
    body = comment_body(line, lang)
    if body is None or len(body) < 12:
        return None
    offset = line.find(body)
    if offset < 0:  # defensive: comment_body returns a substring, so this cannot happen
        offset = 0

    marker = MARKER_RE.match(body)
    rest = body[marker.end():] if marker else body
    rest_offset = offset + (marker.end() if marker else 0)
    addressed = ADDRESSED_RE.search(rest)
    imperative = IMPERATIVE_RE.match(rest)
    authority = AUTHORITY_RE.search(rest)
    negation = UNSAFE_NEGATION_RE.search(rest) or UNSAFE_RAW_RE.search(rest)

    matches = [(klass, severe, m) for klass, severe, rx in OBJECTIVES if (m := rx.search(rest))]
    matches = [m for m in matches if not _prohibited(rest, m[2].start())]
    if not matches:
        return None

    # A hit needs a directive frame — see the module docstring for why descriptive
    # prose that merely names a sink is not reported.
    if not (marker or addressed or imperative or authority or negation):
        return None

    klass, severe, match = min(matches, key=lambda m: (m[2].start(), -len(m[2].group(0))))
    strong = klass not in WEAK_CLASSES
    real_directive = bool(addressed or imperative or negation or authority)
    if strong:
        # An order to build one of the injected-weakness classes. The marker itself is
        # the attack vector — the paper's payloads all wear `# TODO:`/`# INSTRUCTION:`.
        severity = "critical"
    elif real_directive:
        severity = "high"
    else:
        # A marker-only mention of a class respectable code also talks about
        # ("# TODO: log the password"): worth reporting, not worth blocking by itself.
        severity = "medium"
    frames = [
        name
        for name, value in (
            ("marker", marker),
            ("addressed", addressed),
            ("imperative", imperative),
            ("authority", authority),
            ("unsafe-negation", negation),
        )
        if value
    ]
    return Finding(
        line=line_no,
        klass=klass,
        severity=severity,
        body=body,
        frames=frames,
        char_range=(rest_offset + match.start(), rest_offset + match.end()),
    )


def scan_lines(text: str, *, lang: str | None = "hash") -> list[Finding]:
    """Classify every line of ``text`` (1-based line numbers)."""
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        found = classify_line(line, line_no=i, lang=lang)
        if found is not None:
            findings.append(found)
    return findings


class CommentDirectiveDetector(Detector):
    """DET-008: insecure instruction hidden in an ordinary code comment."""

    id = "DET-008"
    name = "comment_directive"
    description = (
        "Insecure instruction embedded in an ordinary code comment or agent rule file "
        "(inference-time context injection)."
    )
    supported_kinds = frozenset({"text"})
    default_severity = Severity.HIGH

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        default_lang = doc.metadata.get("lang")
        evidence: list[Evidence] = []
        for para in doc.paragraphs:
            lang = para.raw.get("lang", default_lang)
            found = classify_line(para.text, line_no=para.index or 0, lang=lang)
            if found is None:
                continue
            evidence.append(
                self.make_evidence(
                    title=f"Insecure instruction in a code comment ({found.klass})",
                    description=(
                        f"Line {found.line} of {doc.source_name} carries a "
                        f"{found.klass.replace('_', ' ')} objective written as an ordinary comment "
                        f"(frames: {', '.join(found.frames)}). A Code LLM cannot tell this directive "
                        "from the developer's own — it is in the same marker space "
                        "(`# TODO:` / `# INSTRUCTION:` / `# TASK:`). Treat the comment as data, not "
                        "as an instruction."
                    ),
                    location=Location(
                        source=doc.source_name,
                        paragraph=found.line,
                        char_range=found.char_range,
                        element=f"line:{found.line}",
                    ),
                    severity=_SEVERITY_BY_NAME.get(found.severity, Severity.HIGH),
                    raw={
                        "class": found.klass,
                        "frames": found.frames,
                        "line": found.line,
                        "lang": lang,
                        "comment": found.body,
                    },
                )
            )
        return evidence
