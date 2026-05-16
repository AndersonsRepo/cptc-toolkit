// ============================================================================
//  VULNERABILITY ASSESSMENT REPORT — Typst template v2
//  Pattern-mined from CPTC10 finalists (Finals B / C / E / G / I / K)
//
//  What's new vs. v1
//   • Per-page brand band header w/ classification pill         (C, G, K)
//   • Risk × Sophistication × Remediation triptych per finding  (I)
//   • Banded CVSS criteria rubric table (optional per finding)  (K)
//   • 5×5 Likelihood × Impact risk matrix in methodology        (E)
//   • Severity-count strip in executive summary                  (K)
//   • Status pills: open / rediscovered / in-progress /remediated (E)
//   • Big numbered finding headings with brand-color underline   (E, I)
//   • Cover page: full-bleed brand band + accent rule
//
//  Edit the EDIT section, then add findings with #finding(...).
//  Stable finding IDs (F-001 …) auto-populate the Report Card,
//  Remediation Roadmap, and Severity Strip.
// ============================================================================


// ── 1. REPORT METADATA  ────────────────────────────────  EDIT ──────────────
#let client          = "OuiCroissant"
#let report_title    = "External Penetration Test Report"
#let engagement_id   = "ENG-2026-001"
#let report_date     = datetime(year: 2026, month: 5, day: 16)
#let report_version  = "1.0"
#let classification  = "CONFIDENTIAL"
#let assessor_org    = "[YOUR FIRM]"
#let authors         = ("Jane Doe — Lead Tester", "John Smith — Reviewer")
#let recipients      = ("Alex Client — CISO", "Sam Stakeholder — Director of IT")
#let engagement_start = "May 1, 2026"
#let engagement_end   = "May 14, 2026"

// Network topology — set to a relative image path (e.g. "topology.png")
// to render it as a figure in the Network Topology chapter. Leave as
// `none` to show a placeholder. PNG / SVG / JPG all work.
#let topology_image   = none
#let topology_caption = "In-scope network — DMZ, application tier, and identity layer."


// ── 2. BRAND + COLOR TOKENS  ────────────────────────────────────────────────
#let BRAND = (
  primary: rgb("#2d1b4e"),   // deep purple band
  accent:  rgb("#7c3aed"),   // vibrant accent
  warn:    rgb("#dc2626"),   // classification pill
  soft:    rgb("#f8fafc"),
  border:  rgb("#e2e8f0"),
  code:    rgb("#f1f5f9"),
  muted:   rgb("#64748b"),
  band:    rgb("#3b2f5e"),   // table band header
)

#let SEVERITY = (
  critical: (color: rgb("#7f1d1d"), label: "Critical", rank: 5),
  high:     (color: rgb("#b91c1c"), label: "High",     rank: 4),
  medium:   (color: rgb("#d97706"), label: "Medium",   rank: 3),
  low:      (color: rgb("#65a30d"), label: "Low",      rank: 2),
  info:     (color: rgb("#475569"), label: "Info",     rank: 1),
)

// Status pill palette (for retest / rediscovery)
#let STATUS = (
  open:           (color: SEVERITY.high.color,    label: "Open"),
  rediscovered:   (color: rgb("#9333ea"),         label: "Rediscovered"),
  "in-progress":  (color: SEVERITY.medium.color,  label: "In Progress"),
  remediated:     (color: SEVERITY.low.color,     label: "Remediated"),
  accepted:       (color: BRAND.muted,            label: "Risk Accepted"),
)

// Triptych axis color maps
//   Risk:           high level = bad   (red)  → low = good (green)
//   Sophistication: low level  = bad   (red)  → high = good (green)
//   Remediation:    high level = bad   (red)  → low = good (green)
#let AXIS_COLOR = (
  risk:           (high: SEVERITY.critical.color, medium: SEVERITY.medium.color, low: SEVERITY.low.color),
  sophistication: (low: SEVERITY.critical.color,  medium: SEVERITY.medium.color, high: SEVERITY.low.color),
  remediation:    (high: SEVERITY.critical.color, medium: SEVERITY.medium.color, low: SEVERITY.low.color),
)


// ── 3. DOCUMENT-WIDE PAGE / TEXT SETUP  ─────────────────────────────────────
#set document(title: report_title + " — " + client, author: assessor_org)
#set text(size: 10.5pt, fill: rgb("#0f172a"))
#set par(justify: true, leading: 0.7em)
#set heading(numbering: "1.1")

#set page(
  paper: "us-letter",
  margin: (x: 0.85in, top: 1.05in, bottom: 0.95in),
  header-ascent: 0pt,
  footer-descent: 0pt,
  header: block(
    fill: BRAND.primary,
    width: 100%,
    inset: (x: 10pt, y: 7pt),
    radius: 3pt,
  )[
    #set text(white, weight: "medium", size: 9pt)
    #grid(columns: (auto, 1fr, auto), gutter: 14pt, align: horizon,
      text(weight: "bold", tracking: 0.6pt, upper(report_title)),
      context {
        let hs = query(heading.where(level: 1).before(here()))
        if hs.len() > 0 {
          text(fill: rgb("#cbd5e1"), upper(hs.last().body))
        }
      },
      box(
        fill: BRAND.warn, inset: (x: 8pt, y: 2pt), radius: 999pt,
        text(white, weight: "bold", size: 7.5pt, tracking: 0.8pt,
          upper(classification))
      ),
    )
  ],
  footer: [
    #line(length: 100%, stroke: 0.6pt + BRAND.accent)
    #v(4pt)
    #grid(columns: (1fr, auto, 1fr), align: (left, center, right),
      text(size: 8pt, fill: BRAND.muted)[#assessor_org · #client],
      text(size: 8pt, fill: BRAND.muted)[
        #context [Page #counter(page).display() of #counter(page).final().first()]
      ],
      text(size: 8pt, fill: BRAND.muted)[
        #report_date.display("[year]-[month]-[day]") · v#report_version
      ],
    )
  ],
  numbering: "1",
)

// Heading show rules — big numbered title with brand rule (CPTC10 E/I style)
#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  v(0.4em)
  block[
    #text(size: 11pt, fill: BRAND.accent, weight: "medium", tracking: 2pt)[
      #upper[Chapter #counter(heading).display()]
    ]
    #v(2pt)
    #text(size: 26pt, weight: "bold", fill: BRAND.primary, it.body)
    #v(4pt)
    #line(length: 60pt, stroke: 2pt + BRAND.accent)
  ]
  v(0.8em)
}
#show heading.where(level: 2): it => {
  v(0.9em)
  block[
    #text(size: 16pt, weight: "bold", fill: BRAND.primary)[
      #counter(heading).display() #h(0.4em) #it.body
    ]
    #v(2pt)
    #line(length: 100%, stroke: 0.5pt + BRAND.border)
  ]
  v(0.2em)
}
#show heading.where(level: 3): it => {
  v(0.6em)
  text(size: 12pt, weight: "bold", fill: BRAND.primary.darken(10%))[
    #counter(heading).display() #h(0.3em) #it.body
  ]
  v(0.1em)
}
#show heading.where(level: 4): it => {
  v(0.4em)
  text(size: 10.5pt, weight: "bold", fill: BRAND.primary.darken(10%), it.body)
  v(0.05em)
}

// Code blocks (CPTC10 evidence sections)
#show raw.where(block: true): it => block(
  fill: BRAND.code, inset: 10pt, radius: 4pt, width: 100%,
  stroke: (left: 3pt + BRAND.accent, rest: 0.5pt + BRAND.border),
  text(size: 9pt, font: ("Menlo", "Consolas", "DejaVu Sans Mono"), it),
)
#show raw.where(block: false): it => box(
  fill: BRAND.code, inset: (x: 4pt, y: 0pt), outset: (y: 2pt),
  radius: 2pt,
  text(size: 9.5pt, font: ("Menlo", "Consolas", "DejaVu Sans Mono"), it),
)
#show link: it => underline(text(fill: BRAND.accent, it))


// ── 4. HELPER FUNCTIONS  ────────────────────────────────────────────────────
#let pill(content, fill: BRAND.soft, stroke-color: BRAND.border,
          text-fill: black, size: 8pt) = box(
  fill: fill, stroke: 0.5pt + stroke-color, radius: 999pt,
  inset: (x: 8pt, y: 2pt),
  text(size: size, weight: "medium", fill: text-fill, content),
)

#let sev-pill(severity) = {
  let s = SEVERITY.at(severity)
  pill(upper(s.label), fill: s.color, stroke-color: s.color, text-fill: white)
}

#let status-pill(status) = {
  let s = STATUS.at(status)
  pill(upper(s.label), fill: s.color, stroke-color: s.color, text-fill: white)
}

#let cvss-badge(score, severity) = {
  let s = SEVERITY.at(severity)
  box(width: 46pt, height: 46pt, fill: s.color, radius: 999pt,
    stroke: 2pt + s.color.lighten(20%),
    align(center + horizon, text(
      fill: white, weight: "bold", size: 14pt, str(score),
    ))
  )
}

#let callout(title, body, color: BRAND.accent) = block(
  fill: color.lighten(90%),
  stroke: (left: 3pt + color),
  inset: 12pt, width: 100%, radius: (right: 4pt),
  [#text(weight: "bold", fill: color, title) \ #body]
)

// CPTC10 Finals-I triptych: Risk | Sophistication | Remediation as colored row
#let triptych(risk: "high", sophistication: "low", remediation: "high") = {
  let cell(label, axis, level) = {
    let color = AXIS_COLOR.at(axis).at(level)
    block(fill: color, inset: 10pt, width: 100%, [
      #set text(white, weight: "bold")
      #align(center, [
        #text(size: 8pt, tracking: 1pt, upper(label)) \
        #v(2pt)
        #text(size: 14pt, upper(level))
      ])
    ])
  }
  grid(columns: (1fr, 1fr, 1fr), column-gutter: 4pt,
    cell("Risk", "risk", risk),
    cell("Sophistication", "sophistication", sophistication),
    cell("Remediation", "remediation", remediation),
  )
}

// CPTC10 Finals-K banded CVSS criteria rubric table (2×4 layout)
#let cvss-criteria-table(criteria) = {
  let pairs = (
    ("Attack Vector",     criteria.at("av",  default: "—")),
    ("Attack Complexity", criteria.at("ac",  default: "—")),
    ("Privileges Req'd",  criteria.at("pr",  default: "—")),
    ("User Interaction",  criteria.at("ui",  default: "—")),
    ("Scope",             criteria.at("s",   default: "—")),
    ("Confidentiality",   criteria.at("c",   default: "—")),
    ("Integrity",         criteria.at("i",   default: "—")),
    ("Availability",      criteria.at("a",   default: "—")),
  )
  table(
    columns: (auto, 1fr, auto, 1fr),
    inset: (x: 10pt, y: 6pt),
    stroke: 0.5pt + BRAND.border,
    fill: (_, y) => if y == 0 { BRAND.band } else { none },
    table.cell(colspan: 4,
      text(white, weight: "bold", size: 9pt, tracking: 0.8pt,
        upper("CVSS v3.1 Criteria"))),
    ..range(0, pairs.len(), step: 2).map(i => {
      let left = pairs.at(i)
      let right = if i + 1 < pairs.len() { pairs.at(i + 1) } else { ("", "") }
      (
        text(size: 8pt, weight: "bold", fill: BRAND.muted, left.at(0)),
        text(size: 9.5pt, left.at(1)),
        text(size: 8pt, weight: "bold", fill: BRAND.muted, right.at(0)),
        text(size: 9.5pt, right.at(1)),
      )
    }).flatten()
  )
}

// CPTC10 Finals-E heuristic Likelihood × Impact risk matrix
#let risk-matrix() = {
  let axis = ("Very Low", "Low", "Medium", "High", "Very High")
  let short = ("VL", "L", "M", "H", "C")
  // matrix[likelihood][impact] = severity rank 0..4
  let m = (
    (0, 0, 1, 1, 2),
    (0, 1, 1, 2, 3),
    (1, 1, 2, 3, 3),
    (1, 2, 3, 3, 4),
    (2, 3, 3, 4, 4),
  )
  let palette = (
    SEVERITY.info.color,
    SEVERITY.low.color,
    SEVERITY.medium.color,
    SEVERITY.high.color,
    SEVERITY.critical.color,
  )
  table(
    columns: 6,
    inset: 8pt,
    stroke: 0.5pt + BRAND.border,
    align: center + horizon,
    table.cell(rowspan: 1, colspan: 1,
      text(size: 8pt, fill: BRAND.muted, weight: "bold")[L \\ I]),
    ..axis.map(a => text(size: 9pt, weight: "bold", a)),
    ..range(0, 5).map(y => {
      let row = m.at(4 - y)  // top row = highest likelihood
      (
        text(size: 9pt, weight: "bold", axis.at(4 - y)),
        ..row.map(v => table.cell(
          fill: palette.at(v),
          text(white, weight: "bold", size: 11pt, short.at(v)),
        ))
      )
    }).flatten()
  )
}


// ── 4b. ATTACK-PATH HELPER (v0.2 — BloodHound / AD chains)  ─────────────────
// Renders an AD compromise chain as a vertical flow inside a finding's
// `evidence:` block. Each step is a dict:
//   (kind: "User"|"Group"|"Computer"|"CertTemplate"|"Domain"|"OU"|"GPO"|"...",
//    name: "JANE@CORP.LOCAL",
//    edge-out: "HasSession")   // optional; omit on the final step
#let attack-path(steps, title: none) = block(
  fill: BRAND.soft,
  stroke: 0.5pt + BRAND.border,
  inset: 14pt,
  radius: 6pt,
  width: 100%,
  [
    #if title != none [
      #text(size: 8pt, fill: BRAND.muted, weight: "bold", tracking: 0.8pt)[
        #upper(title)
      ]
      #v(8pt)
    ]
    #for (i, step) in steps.enumerate() {
      // Node row: [KIND tag] + node name
      block(width: 100%, [
        #stack(dir: ltr, spacing: 10pt,
          box(
            fill: BRAND.primary, inset: (x: 8pt, y: 3pt), radius: 3pt,
            text(white, size: 7.5pt, weight: "bold", tracking: 0.8pt,
              upper(step.at("kind", default: "node"))),
          ),
          text(size: 11pt, weight: "bold", step.at("name", default: "?")),
        )
      ])
      // Edge row (skip on final step)
      let edge = step.at("edge-out", default: none)
      if edge != none {
        block(width: 100%, inset: (left: 6pt, top: 2pt, bottom: 2pt), [
          #stack(dir: ltr, spacing: 8pt,
            text(size: 14pt, fill: BRAND.accent, weight: "bold")[↓],
            text(size: 9pt, fill: BRAND.muted, style: "italic", edge),
          )
        ])
      }
    }
  ]
)


// ── 5. FINDING STATE + MACRO  ───────────────────────────────────────────────
#let findings-state = state("findings", ())

#let finding(
  id: "F-XXX",
  title: "[FINDING TITLE]",
  severity: "medium",
  cvss-score: 0.0,
  cvss-vector: "",
  cvss-criteria: none,     // dict — (av:, ac:, pr:, ui:, s:, c:, i:, a:)
  hosts: (),
  impact: "Medium",
  likelihood: "Medium",
  status: "open",          // open | rediscovered | in-progress | remediated | accepted
  // Triptych axes (CPTC10 Finals-I)
  axis-risk: none,           // critical | high | medium | low
  axis-sophistication: none, // low | medium | high
  axis-remediation: none,    // low | medium | high
  description: [],
  business-impact: [],
  evidence: [],
  remediation: [],
  mitre-attack: (),
  cwe: (),
  owasp: (),
  compliance: (),
  references: (),
) = {
  findings-state.update(fs => fs + ((
    id: id, title: title, severity: severity,
    cvss-score: cvss-score, hosts: hosts, status: status,
    remediation-text: remediation,
  ),))

  let s = SEVERITY.at(severity)

  // Build the references block
  let ref-rows = ()
  if mitre-attack.len() > 0 { ref-rows.push(([MITRE ATT&CK], mitre-attack.join(", "))) }
  if cwe.len() > 0          { ref-rows.push(([CWE], cwe.join(", "))) }
  if owasp.len() > 0        { ref-rows.push(([OWASP], owasp.join(", "))) }
  if compliance.len() > 0   { ref-rows.push(([Compliance], compliance.join(", "))) }
  if references.len() > 0   { ref-rows.push(([References], references.map(r => link(r)).join(", "))) }

  figure(
    kind: "finding",
    supplement: [Finding],
    numbering: none,
    block(
      breakable: true,
      width: 100%,
      stroke: (left: 5pt + s.color, rest: 0.5pt + BRAND.border),
      radius: (right: 6pt),
      inset: 0pt,
      [
        // ────── Header strip with CVSS badge + title + sev pill + status
        #block(fill: s.color.lighten(94%), inset: 14pt, width: 100%, [
          #grid(
            columns: (auto, 1fr, auto),
            column-gutter: 14pt,
            align: (horizon + left, horizon + left, horizon + right),
            cvss-badge(cvss-score, severity),
            [
              #text(size: 9pt, fill: BRAND.muted, weight: "medium",
                tracking: 0.6pt, upper(raw(id)))
              #v(-4pt)
              #text(size: 16pt, weight: "bold", fill: BRAND.primary, title)
            ],
            stack(dir: ltr, spacing: 6pt,
              sev-pill(severity),
              pill(text(weight: "bold")[CVSS #cvss-score],
                fill: BRAND.soft, stroke-color: BRAND.border),
              status-pill(status),
            ),
          )
        ])

        // ────── Triptych (Risk | Sophistication | Remediation)
        #if axis-risk != none and axis-sophistication != none and axis-remediation != none [
          #block(inset: (x: 14pt, top: 12pt, bottom: 6pt), width: 100%,
            triptych(
              risk: axis-risk,
              sophistication: axis-sophistication,
              remediation: axis-remediation,
            )
          )
        ]

        // ────── Meta row (Impact / Likelihood / Affected scope)
        #block(inset: 14pt, width: 100%, stroke: (top: 0.5pt + BRAND.border), [
          #grid(columns: (1fr, 1fr, 2fr), column-gutter: 14pt, row-gutter: 6pt,
            [
              #text(size: 8pt, fill: BRAND.muted, weight: "bold",
                tracking: 0.6pt)[IMPACT]
              #v(-2pt)
              #text(size: 11pt, impact)
            ],
            [
              #text(size: 8pt, fill: BRAND.muted, weight: "bold",
                tracking: 0.6pt)[LIKELIHOOD]
              #v(-2pt)
              #text(size: 11pt, likelihood)
            ],
            [
              #text(size: 8pt, fill: BRAND.muted, weight: "bold",
                tracking: 0.6pt)[AFFECTED SCOPE]
              #v(-2pt)
              #if hosts.len() > 0 [
                #hosts.map(h => raw(h)).join(", ")
              ] else [—]
            ],
          )
          #if cvss-vector != "" [
            #v(6pt)
            #text(size: 8pt, fill: BRAND.muted, weight: "bold",
              tracking: 0.6pt)[CVSS VECTOR] \
            #raw(cvss-vector)
          ]
        ])

        // ────── Optional banded CVSS criteria rubric table
        #if cvss-criteria != none [
          #block(inset: 14pt, width: 100%, stroke: (top: 0.5pt + BRAND.border),
            cvss-criteria-table(cvss-criteria)
          )
        ]

        // ────── Body — description / impact / evidence / remediation
        #block(inset: 14pt, width: 100%, stroke: (top: 0.5pt + BRAND.border), [
          #text(size: 8pt, fill: BRAND.muted, weight: "bold",
            tracking: 0.6pt)[VULNERABILITY DESCRIPTION]
          #v(3pt); #description
          #v(12pt)
          #text(size: 8pt, fill: BRAND.muted, weight: "bold",
            tracking: 0.6pt)[BUSINESS IMPACT]
          #v(3pt); #business-impact
          #if evidence != [] [
            #v(12pt)
            #text(size: 8pt, fill: BRAND.muted, weight: "bold",
              tracking: 0.6pt)[PROOF OF CONCEPT / EVIDENCE]
            #v(3pt); #evidence
          ]
          #v(12pt)
          #text(size: 8pt, fill: BRAND.muted, weight: "bold",
            tracking: 0.6pt)[REMEDIATION]
          #v(3pt); #remediation
          #if ref-rows.len() > 0 [
            #v(12pt)
            #block(fill: BRAND.soft, inset: 10pt, radius: 4pt, width: 100%,
              table(columns: (auto, 1fr), column-gutter: 14pt,
                row-gutter: 4pt, stroke: none, inset: 2pt,
                ..ref-rows.map(r => (
                  text(size: 8pt, weight: "bold", fill: BRAND.muted, r.at(0)),
                  text(size: 9pt, r.at(1)),
                )).flatten()
              )
            )
          ]
        ])

        // ────── Footer hairline w/ finding ID
        #block(fill: BRAND.soft, inset: (x: 14pt, y: 5pt), width: 100%,
          stroke: (top: 0.5pt + BRAND.border),
          align(right, text(size: 8pt, fill: BRAND.muted)[
            #raw(id) · #upper(severity) · CVSS #cvss-score
          ])
        )
      ]
    )
  )
  v(0.8em)
}


// ── 6. AGGREGATORS  ─────────────────────────────────────────────────────────
// CPTC10 Finals-K severity-count strip
#let severity-strip() = context {
  let fs = findings-state.final()
  let order = ("critical", "high", "medium", "low", "info")
  let counts = order.map(s => (s, fs.filter(f => f.severity == s).len()))
  table(
    columns: (1fr, 1fr, 1fr, 1fr, 1fr),
    align: center + horizon,
    inset: 10pt,
    stroke: none,
    fill: (col, _) => SEVERITY.at(order.at(col)).color,
    ..counts.map(c => [
      #set text(white)
      #text(size: 7.5pt, weight: "medium", tracking: 1pt,
        upper(SEVERITY.at(c.at(0)).label))
      #v(2pt)
      #text(size: 22pt, weight: "bold", str(c.at(1)))
    ]),
  )
}

// Severity-by-count proportional bar (kept from v1)
#let severity-bar() = context {
  let fs = findings-state.final()
  let order = ("critical", "high", "medium", "low", "info")
  if fs.len() == 0 { return [_No findings recorded._] }
  let counts = order.map(s => (s, fs.filter(f => f.severity == s).len()))
  let total = fs.len()
  block(width: 100%, [
    #box(width: 100%, height: 22pt, fill: BRAND.soft, radius: 4pt,
      stack(dir: ltr,
        ..counts.filter(c => c.at(1) > 0).map(c => rect(
          width: (c.at(1) / total) * 100%,
          height: 22pt,
          fill: SEVERITY.at(c.at(0)).color,
          stroke: none,
        ))
      )
    )
    #v(6pt)
    #text(size: 8pt, fill: BRAND.muted)[
      Distribution by severity, weighted by count (total: #total findings).
    ]
  ])
}

#let report-card() = context {
  let fs = findings-state.final()
  if fs.len() == 0 { return [_No findings to summarize._] }
  let sorted = fs.sorted(key: f => -SEVERITY.at(f.severity).rank)
  table(
    columns: (auto, 1fr, auto, auto, auto, auto),
    inset: (x: 10pt, y: 8pt),
    stroke: 0.5pt + BRAND.border,
    fill: (_, y) => if y == 0 { BRAND.band } else { none },
    table.header(
      text(white, weight: "bold", size: 9pt, tracking: 0.6pt)[ID],
      text(white, weight: "bold", size: 9pt, tracking: 0.6pt)[Finding],
      text(white, weight: "bold", size: 9pt, tracking: 0.6pt)[Severity],
      text(white, weight: "bold", size: 9pt, tracking: 0.6pt)[CVSS],
      text(white, weight: "bold", size: 9pt, tracking: 0.6pt)[Status],
      text(white, weight: "bold", size: 9pt, tracking: 0.6pt)[Hosts],
    ),
    ..sorted.map(f => (
      raw(f.id),
      text(size: 9.5pt, f.title),
      sev-pill(f.severity),
      text(weight: "bold", str(f.cvss-score)),
      status-pill(f.status),
      str(f.hosts.len()),
    )).flatten()
  )
}

#let remediation-roadmap() = context {
  let fs = findings-state.final()
  if fs.len() == 0 { return [_No items in the roadmap._] }
  let sorted = fs.sorted(key: f => -SEVERITY.at(f.severity).rank)
  table(
    columns: (auto, auto, 1fr, auto, auto),
    inset: (x: 10pt, y: 8pt),
    stroke: 0.5pt + BRAND.border,
    fill: (_, y) => if y == 0 { BRAND.band } else { none },
    table.header(
      text(white, weight: "bold", size: 9pt)[Priority],
      text(white, weight: "bold", size: 9pt)[ID],
      text(white, weight: "bold", size: 9pt)[Recommended Action],
      text(white, weight: "bold", size: 9pt)[Severity],
      text(white, weight: "bold", size: 9pt)[Status],
    ),
    ..sorted.enumerate().map(((i, f)) => (
      text(weight: "bold", str(i + 1)),
      raw(f.id),
      f.remediation-text,
      sev-pill(f.severity),
      status-pill(f.status),
    )).flatten()
  )
}


// ── 7. COVER PAGE  ──────────────────────────────────────────────────────────
#page(header: none, footer: none, numbering: none, margin: 0pt, [
  // Top brand band — full bleed
  #block(fill: BRAND.primary, width: 100%, height: 33%, [
    #place(top + left, dx: 0.85in, dy: 0.85in,
      text(white, weight: "bold", size: 11pt, tracking: 2pt,
        upper(classification + " · Engagement " + engagement_id)))
    #place(bottom + left, dx: 0.85in, dy: -0.5in,
      rect(width: 60pt, height: 4pt, fill: BRAND.accent.lighten(20%)))
    #place(bottom + right, dx: -0.85in, dy: -0.85in,
      text(white, size: 11pt, weight: "medium",
        report_date.display("[month repr:long] [year]")))
  ])

  // Body
  #v(0.6in)
  #pad(x: 0.85in, [
    #text(size: 11pt, fill: BRAND.muted, weight: "medium", tracking: 1.5pt,
      upper("Prepared for"))
    #v(4pt)
    #text(size: 32pt, weight: "bold", fill: BRAND.primary, client)
    #v(0.6in)
    #text(size: 11pt, fill: BRAND.muted, weight: "medium", tracking: 1.5pt,
      upper("Report"))
    #v(4pt)
    #text(size: 42pt, weight: "bold", fill: black, report_title)
    #v(6pt)
    #line(length: 96pt, stroke: 3pt + BRAND.accent)
  ])

  // Bottom metadata block
  #v(1fr)
  #pad(x: 0.85in, bottom: 0.85in, [
    #line(length: 100%, stroke: 0.5pt + BRAND.border)
    #v(12pt)
    #grid(columns: (1fr, 1fr, 1fr), gutter: 16pt,
      [
        #text(size: 8.5pt, fill: BRAND.muted, weight: "medium", tracking: 1pt,
          upper("Prepared by"))
        #v(4pt)
        #text(size: 11pt, weight: "medium", assessor_org)
      ],
      [
        #text(size: 8.5pt, fill: BRAND.muted, weight: "medium", tracking: 1pt,
          upper("Engagement window"))
        #v(4pt)
        #text(size: 11pt)[#engagement_start — #engagement_end]
      ],
      [
        #text(size: 8.5pt, fill: BRAND.muted, weight: "medium", tracking: 1pt,
          upper("Version"))
        #v(4pt)
        #text(size: 11pt)[v#report_version]
      ],
    )
  ])
])
#counter(page).update(1)


// ── 8. STATEMENT OF CONFIDENTIALITY  ────────────────────────────────────────
= Statement of Confidentiality

This document contains information that is confidential and proprietary to
#client and #assessor_org. It is intended solely for the named recipients
above. No part of this document may be redistributed, copied, or quoted
without the prior written consent of #client.

The findings and recommendations in this report reflect the state of the
target environment during the engagement window
(#engagement_start — #engagement_end) and may not reflect the current state
of the systems described.

#callout(
  [Distribution Restrictions],
  [Treat this report as #strong[#classification]. Do not place on any
   internet-facing storage or share with parties not named in the
   *Recipients* row above without written approval from #client's
   security organization.],
  color: BRAND.warn,
)


// ── 10. CONTENTS  ───────────────────────────────────────────────────────────
= Contents
#outline(title: none, indent: auto, depth: 3)


// ── 11. EXECUTIVE SUMMARY  ──────────────────────────────────────────────────
= Executive Summary

#assessor_org was engaged by #client to perform an external penetration
test against the in-scope assets between #engagement_start and
#engagement_end. The objective was to identify exploitable vulnerabilities
that could be leveraged by an unauthenticated attacker on the public
internet, and to provide prioritized remediation guidance.

The testing team gained #strong[unauthenticated remote code execution] on
a public-facing application and pivoted to internal database systems
containing customer PII. Several supporting weaknesses contributed to the
overall impact and are documented as individual findings below.

== Findings at a Glance
#severity-strip()
#v(8pt)
#severity-bar()

== Top Risks
+ #strong[Unauthenticated RCE on the public web tier (F-001).]
  Allows full compromise of the application host without credentials.
+ #strong[Blind SQL injection in the partner portal (F-002).]
  Enables read access to the entire customer database.
+ #strong[Reflected XSS in the support search field (F-003).]
  Enables account-takeover of authenticated support staff.

== Vulnerability Report Card
#report-card()


// ── 12. KEY STRENGTHS  ──────────────────────────────────────────────────────
= Key Strengths

Following CPTC10 reporting practice, this engagement opens with the
controls that performed well during testing. These should be preserved as
the environment evolves.

- *Modern TLS configuration.* All external endpoints reject TLS 1.0/1.1
  and disable deprecated cipher suites.
- *Restrictive egress filtering.* Compromised hosts had no ability to
  reach arbitrary internet destinations, blunting post-exploitation.
- *Mature OS-package patch cadence.* No findings were attributable to
  missing OS-level security updates.
- *Centralized identity provider.* SSO enrollment is enforced across all
  in-scope SaaS and reduced the value of credential-based attacks.


// ── 13. KEY AREAS FOR IMPROVEMENT  ──────────────────────────────────────────
= Key Areas for Improvement

#enum(numbering: "1.",
  [*Application input validation and output encoding.* Multiple findings
   trace to the same root cause and would be eliminated by a shared
   sanitization layer.],
  [*Secrets management.* Hardcoded credentials and tokens were recovered
   from build artifacts and reachable backup files.],
  [*Network segmentation between DMZ and internal data tier.* Once a DMZ
   host was compromised, no controls prevented direct database access.],
  [*Web Application Firewall coverage.* The current WAF rule set did not
   detect the time-based payloads used during testing.],
)


// ── 14. SCOPE  ──────────────────────────────────────────────────────────────
= Scope

== In-Scope Targets
#table(
  columns: (auto, 1fr, auto),
  inset: 8pt, stroke: 0.5pt + BRAND.border,
  fill: (_, y) => if y == 0 { BRAND.band } else { none },
  text(white, weight: "bold")[Hostname], text(white, weight: "bold")[IP],
    text(white, weight: "bold")[Service],
  [app.example.com],       [203.0.113.10], [HTTPS],
  [api.example.com],       [203.0.113.11], [HTTPS],
  [partners.example.com],  [203.0.113.12], [HTTPS],
  [vpn.example.com],       [203.0.113.20], [IKE/IPsec],
)

== Out-of-Scope
- Third-party SaaS providers
- Production databases (no destructive testing)
- Denial-of-service testing of any kind
- Physical and social-engineering attacks

== Engagement Type
External, grey-box. Testers were provided with one set of standard-user
credentials for the partner portal. No source code or internal network
access was provided.


// ── 14b. NETWORK TOPOLOGY  ──────────────────────────────────────────────────
= Network Topology

The environment under test is summarized below. The diagram identifies
trust boundaries between the public internet, the DMZ application tier,
the internal data tier, and the identity / Active Directory layer.

#if topology_image != none [
  #figure(
    image(topology_image, width: 100%),
    caption: [#topology_caption],
    kind: image,
  )
] else [
  #block(
    width: 100%, inset: 18pt, radius: 6pt,
    stroke: 1pt + BRAND.border, fill: BRAND.soft,
    [
      #set text(fill: BRAND.muted, size: 10pt)
      #align(center, [
        #text(weight: "bold")[Network diagram pending.]
        #v(4pt)
        Set `#raw("#let topology_image = \"path/to/diagram.png\"")` in
        the EDIT block at the top of this report to render the
        environment diagram here.
      ])
    ]
  )
]

== Network Segments
#table(
  columns: (auto, auto, 1fr, auto),
  inset: 8pt, stroke: 0.5pt + BRAND.border,
  fill: (_, y) => if y == 0 { BRAND.band } else { none },
  text(white, weight: "bold")[Segment],
  text(white, weight: "bold")[CIDR],
  text(white, weight: "bold")[Purpose],
  text(white, weight: "bold")[Trust],
  [DMZ — Public Web], [203.0.113.0/29], [Customer + partner-facing apps],     [Untrusted],
  [DMZ — VPN],        [203.0.113.16/29], [Remote-access concentrator],        [Untrusted],
  [Internal — App],   [10.10.10.0/24],   [Application servers, microservices], [Trusted],
  [Internal — Data],  [10.10.20.0/24],   [Databases, file storage],           [Trusted],
  [Internal — AD],    [10.10.30.0/24],   [Domain controllers, identity stack], [Critical],
  [Management],       [10.10.99.0/24],   [Out-of-band admin, jump hosts],     [Critical],
)

== Trust Boundaries
- Public internet → DMZ is the only sanctioned ingress.
- DMZ → Internal is firewalled; only specific application traffic is
  permitted via documented rules.
- Internal → AD is the most sensitive boundary; lateral movement here
  is what most findings in this report ultimately enable.


// ── 15. METHODOLOGY  ────────────────────────────────────────────────────────
= Methodology

Testing followed the Penetration Testing Execution Standard (PTES) phases
and OWASP Web Security Testing Guide (WSTG) checklists.

+ *Reconnaissance* — passive OSINT and DNS enumeration
+ *Scanning & enumeration* — TCP/UDP service discovery, version detection
+ *Vulnerability analysis* — manual + automated, false-positive triage
+ *Exploitation* — controlled, no destructive payloads
+ *Post-exploitation* — privilege escalation, lateral movement modeling
+ *Reporting* — this document

#callout(
  [Rules of Engagement],
  [Active exploitation was performed only during the agreed-upon testing
   window of #engagement_start — #engagement_end, and only against
   in-scope hosts. All exploit payloads were logged and shared with the
   client.],
  color: BRAND.accent,
)


// ── 16. RISK RATING METHODOLOGY  ────────────────────────────────────────────
= Risk Rating Methodology

Each finding receives a CVSS v3.1 base score (numeric) and a qualitative
severity label. The severity bands are:

#table(
  columns: (auto, auto, 1fr),
  inset: (x: 12pt, y: 10pt), stroke: 0.5pt + BRAND.border,
  fill: (_, y) => if y == 0 { BRAND.band } else { none },
  text(white, weight: "bold")[Severity],
  text(white, weight: "bold")[CVSS Range],
  text(white, weight: "bold")[Definition],
  sev-pill("critical"), [9.0 – 10.0],
    [Immediate threat. Compromise of confidentiality, integrity, or availability with no prerequisites.],
  sev-pill("high"),     [7.0 – 8.9],
    [Significant threat. Exploitable with low complexity or low privilege.],
  sev-pill("medium"),   [4.0 – 6.9],
    [Moderate threat. Exploitation requires non-trivial conditions.],
  sev-pill("low"),      [0.1 – 3.9],
    [Limited threat. Low impact and/or high exploitation barrier.],
  sev-pill("info"),     [0.0],
    [Informational. No direct security impact, but worth noting.],
)

== Likelihood × Impact Heuristic
In addition to CVSS, each finding is plotted on the matrix below. The
matrix is used to sanity-check the numeric score against the engagement
context.

#risk-matrix()

#v(8pt)
#text(size: 9pt, fill: BRAND.muted)[
  Cell labels: #strong[VL] very low · #strong[L] low · #strong[M] medium ·
  #strong[H] high · #strong[C] critical. Likelihood (rows) increases
  upward; Impact (columns) increases rightward.
]


// ── 17. COMPLIANCE MAPPING  ─────────────────────────────────────────────────
= Compliance Mapping

The following standards were used as reference frameworks during testing
and are cited in individual findings where applicable:

- *OWASP Top 10:2021* — web application risks
- *PCI-DSS v4.0* — for components touching cardholder data
- *NIST SP 800-53 Rev. 5* — for general control alignment
- *CWE Top 25 (2024)* — for vulnerability classification
- *MITRE ATT&CK Enterprise v15* — for adversary technique mapping


// ── 18. ATTACK NARRATIVE  ───────────────────────────────────────────────────
= Attack Narrative

The compromise chain proceeded as follows:

+ #strong[Recon.] Subdomain enumeration revealed `partners.example.com`,
  hosting a legacy build of the partner portal.
+ #strong[Initial access.] An unauthenticated RCE in the portal's file
  upload handler (#raw("F-001")) granted shell access as the application
  user.
+ #strong[Privilege escalation.] A SUID misconfiguration on
  `/usr/bin/find` allowed escalation to `root`.
+ #strong[Lateral movement.] Database credentials in
  `/opt/app/config/db.yml` enabled direct access to the internal
  customer DB, where blind SQL injection (#raw("F-002")) was
  independently verified.
+ #strong[Persistence (not deployed).] A systemd-timer persistence
  vector was confirmed but not deployed.


// ── 19. FINDINGS  ───────────────────────────────────────────────────────────
= Findings

== Findings (scanner-generated)

// Generated by scanner_to_typst.py — do not hand-edit blindly.
// Each #finding(...) block can be moved to a different severity
// chapter; the report card auto-sorts by severity.
// Comments tagged `// AI-DRAFT:` mark fields drafted by --draft-prose;
// review those before publication.

// Source: nuclei:['pdteam', 'cptc-toolkit']
#finding(
  id: "F-001",
  title: "Unauthenticated Remote Code Execution in File Upload Handler",
  severity: "critical",
  cvss-score: 9.8,
  cvss-vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  cvss-criteria: (av: "Network", ac: "Low", pr: "None", ui: "None", s: "Unchanged", c: "High", i: "High", a: "High"),
  hosts: ("https://partners.example.com", "https://partners.example.com/upload/avatar"),
  impact: "High",
  likelihood: "High",
  status: "open",
  axis-risk: "high",
  axis-sophistication: "low",
  axis-remediation: "medium",
  description: [The /upload/avatar endpoint accepts arbitrary file extensions and writes uploaded files into a directory served directly by the application server. By uploading a .php file containing a webshell and requesting it back, an unauthenticated attacker achieves remote code execution as the application user.],
  business-impact: [\[Business impact pending — write 2–4 sentences in client terms.\]],
  evidence: [*Request*

#raw("POST /upload/avatar HTTP/1.1\nHost: partners.example.com\nContent-Type: multipart/form-data; boundary=---X\n\n-----X\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\nContent-Type: image/jpeg\n\n<?php system($_GET['c']); ?>\n-----X--\n", block: true, lang: "http")


*Response*

#raw("HTTP/1.1 200 OK\nContent-Length: 18\n\n{\"status\":\"ok\"}\n", block: true, lang: "http")


*Extracted*

#raw("GET /uploads/shell.php?c=id → uid=33(www-data) gid=33(www-data) groups=33(www-data)\n", block: true)],
  remediation: [Validate uploaded file content via magic-byte sniffing, not the extension or Content-Type header. Store uploads under a path that is not directly served by the web server. Serve uploads via a controller that sets a forced Content-Disposition: attachment and a narrowed Content-Type. Rotate any secrets reachable from this host.],
  cwe: ("CWE-434", "CWE-862"),
  references: ("https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload", "https://cwe.mitre.org/data/definitions/434.html"),
)

// Source: nuclei:['cptc-toolkit']
#finding(
  id: "F-002",
  title: "Blind SQL Injection in Partner Search",
  severity: "high",
  cvss-score: 8.6,
  cvss-vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
  cvss-criteria: (av: "Network", ac: "Low", pr: "Low", ui: "None", s: "Changed", c: "High", i: "None", a: "None"),
  hosts: ("https://partners.example.com", "https://partners.example.com/partners/search?q=acme"),
  impact: "High",
  likelihood: "Medium",
  status: "open",
  axis-risk: "high",
  axis-sophistication: "low",
  axis-remediation: "low",
  description: [The `q` parameter on GET /partners/search is concatenated directly into a SQL LIKE clause without parameterization. Time-based blind injection was confirmed and used to exfiltrate row counts from `customers` and `payment_methods`.],
  business-impact: [\[Business impact pending — write 2–4 sentences in client terms.\]],
  evidence: [*Request*

#raw("GET /partners/search?q=acme%27%20AND%20SLEEP(5)--%20 HTTP/1.1\nHost: partners.example.com\n", block: true, lang: "http")


*Response*

#raw("HTTP/1.1 200 OK\nContent-Length: 14\n[delay: 5018 ms vs baseline 78 ms]\n", block: true, lang: "http")


*Extracted*

#raw("TIME_DELTA=5018ms vs 78ms baseline → confirmed blind SQLi\n", block: true)],
  remediation: [Rewrite all data-access paths to use parameterized queries (prepared statements or the ORM's bound-parameter API). Add a detection rule for time-based payloads at the WAF tier.],
  cwe: ("CWE-89",),
  references: ("https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/89.html"),
)

// Source: sarif:owasp zap
#finding(
  id: "F-003",
  title: "Reflected XSS in Support Ticket Search",
  severity: "medium",
  cvss-score: 6.1,
  cvss-vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
  cvss-criteria: (av: "Network", ac: "Low", pr: "None", ui: "Required", s: "Changed", c: "Low", i: "Low", a: "None"),
  hosts: ("https://app.example.com/support/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",),
  impact: "Medium",
  likelihood: "Medium",
  status: "open",
  axis-risk: "medium",
  axis-sophistication: "medium",
  axis-remediation: "low",
  description: [Reflected XSS detected on the `q` parameter of /support/search. The unescaped value is rendered inside an inline <script> block.],
  business-impact: [\[Business impact pending — write 2–4 sentences in client terms.\]],
  remediation: [Apply context-aware output encoding (use the templating layer's auto-escape feature) and add a strict Content-Security-Policy header that disables inline scripts.],
  cwe: ("CWE-79",),
  owasp: ("OWASP A03:2021",),
  references: ("https://www.zaproxy.org/docs/alerts/40012/", "https://cwe.mitre.org/data/definitions/79.html", "https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
)


== Active Directory Findings

// Generated by bloodhound_to_typst.py — AD attack chains.
// Each #finding(...) contains a #attack-path(...) flow inside
// its evidence: field. Splice into the main report after the
// adapter-generated scanner findings.

// Source: bloodhound — 6 step(s)
#finding(
  id: "AD-001",
  title: "Domain Admin compromise via Kerberoast + AD CS ESC1",
  severity: "critical",
  cvss-score: 9.0,
  cvss-vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
  cvss-criteria: (av: "Network", ac: "High", pr: "Low", ui: "None", s: "Changed", c: "High", i: "High", a: "High"),
  hosts: ("corp-dc01.corp.local", "corp-ca01.corp.local"),
  impact: "High",
  likelihood: "High",
  status: "open",
  axis-risk: "high",
  axis-sophistication: "low",
  axis-remediation: "medium",
  description: [A standard domain user (JANE) can chain a Kerberoast against the SQLSVC service account with an ESC1-misconfigured certificate template (VulnerableUserCert) to obtain a TGT impersonating any user — including Domain Admins. The path requires no prior elevation; the only prerequisite is an authenticated session on a domain-joined host.],
  business-impact: [Full compromise of the corp.local forest. An attacker who walks this path gains domain-administrator-equivalent control over every host, every account, and every certificate issued in the environment. Recovery requires a full domain-wide credential reset and the revocation/re-issuance of every certificate issued by CORP-CA01.],
  evidence: [
  #attack-path((
    (kind: "User", name: "JANE@CORP.LOCAL", edge-out: "HasSession on CORP-WS07 (initial foothold)"),
    (kind: "Computer", name: "CORP-WS07.CORP.LOCAL", edge-out: "Enumerates SPNs via GetUserSPNs.py"),
    (kind: "User", name: "SQLSVC@CORP.LOCAL", edge-out: "Kerberoastable → 7-char password cracked offline in 4h"),
    (kind: "CertTemplate", name: "VulnerableUserCert (Enrollee Supplies Subject)", edge-out: "Enroll → request cert with subjectAltName = Administrator (ESC1)"),
    (kind: "CertAuthority", name: "CORP-CA01\\corp-ca01-CA", edge-out: "Issues certificate, Rubeus.exe asktgt /user:Administrator /certificate:...pfx"),
    (kind: "Group", name: "DOMAIN ADMINS@CORP.LOCAL"),
  ), title: "Compromise chain — Kerberoast → ESC1 → Domain Admin")
],
  remediation: [Three independent fixes — apply all of them: (1) Set a 30+ character random password on SQLSVC and/or migrate to a Group Managed Service Account (gMSA) to defeat offline Kerberoasting. (2) Remove the `ENROLLEE_SUPPLIES_SUBJECT` flag from the VulnerableUserCert template, or restrict its enrollment ACL to a known-good security group. (3) Audit AD CS templates with `Certify.exe find /vulnerable` and remediate every ESC1–ESC8 finding, not only this one.],
  mitre-attack: ("T1558.003 — Kerberoasting", "T1649 — Steal or Forge Authentication Certificates", "T1078.002 — Valid Accounts: Domain Accounts"),
  cwe: ("CWE-732", "CWE-269"),
  compliance: ("NIST SP 800-53 AC-6 (Least Privilege)", "CIS Controls v8 5.4"),
  references: ("https://specterops.io/blog/2022/06/21/certified-pre-owned/", "https://github.com/GhostPack/Certify", "https://attack.mitre.org/techniques/T1558/003/", "https://cwe.mitre.org/data/definitions/732.html"),
)


// ── 20. REMEDIATION ROADMAP  ────────────────────────────────────────────────
= Remediation Roadmap

Findings are ordered by severity. Each row references the canonical
finding by ID.

#remediation-roadmap()


// ── 21. APPENDICES  ─────────────────────────────────────────────────────────
#counter(heading).update(0)
#set heading(numbering: "A.1")

= Appendix — Tools Used
- *Reconnaissance*: amass, subfinder, httpx
- *Scanning*: nmap, masscan, nuclei
- *Web testing*: Burp Suite Pro, sqlmap, ffuf
- *Post-exploitation*: linpeas, BloodHound, CrackMapExec
- *Reporting*: Typst, this template

= Appendix — Glossary
- *CVSS*: Common Vulnerability Scoring System
- *CWE*: Common Weakness Enumeration
- *MITRE ATT&CK*: Adversarial Tactics, Techniques, and Common Knowledge
- *OSINT*: Open-Source Intelligence
- *PoC*: Proof of Concept
- *RCE*: Remote Code Execution
- *XSS*: Cross-Site Scripting

= Appendix — Severity / Status Legend
#table(
  columns: (auto, 1fr),
  inset: (x: 12pt, y: 10pt), stroke: 0.5pt + BRAND.border,
  fill: (_, y) => if y == 0 { BRAND.band } else { none },
  text(white, weight: "bold")[Severity],
  text(white, weight: "bold")[Action SLA],
  sev-pill("critical"), [Patch within 24 hours],
  sev-pill("high"),     [Patch within 7 days],
  sev-pill("medium"),   [Patch within 30 days],
  sev-pill("low"),      [Patch within 90 days],
  sev-pill("info"),     [Track for future review],
)

#v(12pt)

#table(
  columns: (auto, 1fr),
  inset: (x: 12pt, y: 10pt), stroke: 0.5pt + BRAND.border,
  fill: (_, y) => if y == 0 { BRAND.band } else { none },
  text(white, weight: "bold")[Status],
  text(white, weight: "bold")[Meaning],
  status-pill("open"),         [Confirmed during this engagement and not yet addressed.],
  status-pill("rediscovered"), [Reported in a prior engagement and re-observed in this one.],
  status-pill("in-progress"),  [Remediation work has begun and is being verified.],
  status-pill("remediated"),   [Verified as fixed during retest.],
  status-pill("accepted"),     [Client has formally accepted the risk.],
)
