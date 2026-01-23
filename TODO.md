# Pwnomicon Standardization Progress

This file tracks the progress of standardizing all documentation to match [STYLE_GUIDE.md](STYLE_GUIDE.md).

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| ⬜ | Not started |
| 🟡 | In progress (partial) |
| ✅ | Completed |
| 📝 | Placeholder only (needs content first) |

---

## Files with Content (Need Standardization)

| Status | File | Lines | Notes |
|--------|------|-------|-------|
| ✅ | `00-general.md` | 1061 | Standardized |
| ⬜ | `01-footprinting.md` | 564 | Needs review |
| ⬜ | `02-information-gathering.md` | 313 | Needs review |
| ✅ | `03-vulnerability-assessment.md` | 195 | Standardized |
| ⬜ | `04-file-transfers.md` | 1098 | Needs review |
| ⬜ | `05-shells-payloads.md` | 924 | Needs review |
| ⬜ | `06-metasploit-framework.md` | 1382 | Needs review |
| ⬜ | `07-password-attacks.md` | 6991 | Largest file, old style |
| ⬜ | `08-common-services.md` | 4120 | Large file |
| ⬜ | `09-pivoting-tunneling.md` | 2483 | Most recent style, use as reference |

---

## Placeholder Files (Need Content)

| Status | File | Notes |
|--------|------|-------|
| 📝 | `10-active-directory.md` | Title only |
| 📝 | `11-web-proxies.md` | Title only |
| 📝 | `12-web-apps-ffuf.md` | Title only |
| 📝 | `13-login-brute-forcing.md` | Title only |
| 📝 | `14-sql-injection-fundamentals.md` | Title only |
| 📝 | `15-sqlmap-essentials.md` | Title only |
| 📝 | `16-xss.md` | Title only |
| 📝 | `17-file-inclusion.md` | Title only |
| 📝 | `18-file-upload-attacks.md` | Title only |
| 📝 | `19-command-injections.md` | Title only |
| 📝 | `20-web-attacks.md` | Title only |
| 📝 | `21-attacking-common-applications.md` | Title only |
| 📝 | `22-linux-privilege-escalation.md` | Title only |
| 📝 | `23-windows-privilege-escalation.md` | Title only |
| 📝 | `24-attacking-enterprise-networks.md` | Title only |

---

## Session Log

Use this section to track progress across sessions.

### Session 1 — 2025-01-23
- Created `STYLE_GUIDE.md`
- Created `TODO.md`
- ✅ Standardized `03-vulnerability-assessment.md` (57 → 195 lines)
  - Added HTML tables for all commands
  - Added numbered instructions with bold verbs
  - Fixed error: duplicate "Start" → "Stop"
  - Added tool descriptions and notes
- ✅ Standardized `00-general.md` (1023 → 1061 lines)
  - Fixed unclosed `</h2>` tags (4 instances)
  - Changed Ping Sweep from `<h3>` to `<h2>`
  - Converted Meterpreter block to HTML table
  - Converted SecLists paths to HTML table

---

## Notes

- **Reference file:** `09-pivoting-tunneling.md` has the most up-to-date style
- **Largest files:** `07-password-attacks.md` (6991 lines), `08-common-services.md` (4120 lines)
- **Strategy:** Work one file at a time, commit after each completion
