# Blackbox Umbra — Brand & Visual Identity Guide

## Logo

```
 ██╗   ██╗███╗   ███╗██████╗ ██████╗  █████╗
 ██║   ██║████╗ ████║██╔══██╗██╔══██╗██╔══██╗
 ██║   ██║██╔████╔██║██████╔╝██████╔╝███████║
 ██║   ██║██║╚██╔╝██║██╔══██╗██╔══██╗██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║██████╔╝██║  ██║██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Wordmark:** "Blackbox Umbra"

---

## Color Palette

### Primary Colors

| Use | Hex | RGB | Name |
|-----|-----|-----|------|
| **Primary** | `#B44A1A` | `180, 74, 26` | Dark Orange |
| **Secondary** | `#07090C` | `7, 9, 12` | Deep Black |
| **Accent** | `#FF5A66` | `255, 90, 102` | Red |

### Supporting Colors

| Use | Hex | RGB | Name |
|-----|-----|-----|------|
| **Neutral** | `#A8B2C0` | `168, 178, 192` | Steel Blue-Gray |
| **Success** | `#00D084` | `0, 208, 132` | Mint Green |
| **Warning** | `#FFA500` | `255, 165, 0` | Amber |
| **Error** | `#C0392B` | `192, 57, 43` | Crimson |
| **Background** | `#0F1419` | `15, 20, 25` | Charcoal Black |

---

## Typography

- **Headings:** Inter, Helvetica Neue, sans-serif (bold, uppercase for major titles)
- **Body Text:** Fira Code, Courier New, monospace (technical documentation)
- **Size Hierarchy:**
  - H1 (Project Title): 32-36px
  - H2 (Section): 24-28px
  - H3 (Subsection): 18-22px
  - Body: 14-16px
  - Code: 12-13px monospace

---

## Visual Elements

### Tagline
```
"The shadow sees all."
```
*Use in marketing, documentation, and all external communications.*

### Icon Concepts

#### Shadow Symbol (Stylized)
```
  ▓▓▓↓
 ▓▓▓▓▓
▓▓▓▓▓▓▓
 ▓▓▓▓▓▓
  ▓▓▓▓
```
*Represents stealth, reconnaissance, and threat detection.*

#### Scanning Lines (Recon)
```
╔═════════╗
║ ▬ ▬ ▬ ▬ ║
║ ▬ ▬ ▬ ▬ ║
║ ▬ ▬ ▬ ▬ ║
╚═════════╝
```
*Represents automated scanning & discovery.*

---

## Usage Guidelines

### Logos & Wordmarks

✅ **DO:**
- Use the full "Blackbox Umbra" wordmark on first mention
- Use dark orange (#B44A1A) for primary text
- Scale proportionally without distortion
- Maintain adequate white space (1x logo height minimum)

❌ **DON'T:**
- Use stretched, compressed, or rotated logos
- Change colors without approval
- Remove the ASCII art identity
- Obscure the "Blackbox Intelligence Group LLC" attribution

### Color Usage

✅ **DO:**
- Use dark orange (#B44A1A) for calls-to-action and highlights
- Use deep black (#07090C) for backgrounds and solid text
- Use steel (#A8B2C0) for secondary text and borders
- Use red (#FF5A66) exclusively for CRITICAL/vulnerability alerts

❌ **DON'T:**
- Invert colors without reason
- Use light backgrounds (maintenance/accessibility issues)
- Mix brand colors randomly
- Use RGB hex colors outside the defined palette

### Documentation

All external documentation (README, guides, blogs) should:
1. **Lead with the ASCII logo** (high impact)
2. **Include tagline** ("The shadow sees all.")
3. **Use dark orange accent** for key terms
4. **Follow typography hierarchy** (H1 → H2 → H3)
5. **End with Blackbox Intelligence Group branding** and website

---

## Asset Files

| Asset | Location | Format | Notes |
|-------|----------|--------|-------|
| Logo | ASCII (inline) | `.md` | Renders in all GitHub/markdown viewers |
| Favicon | — | — | Optional: add 32x32 `.ico` in `.github/` |
| Brand Colors | This file | Reference | Copy hex values from here |
| Tagline | This file | Text | "The shadow sees all." |

---

## Applying Branding

### In Markdown Files
```markdown
# Blackbox Umbra

**Professional penetration testing automation.**

> *The shadow sees all.*
```

### In Terminal Output (Python Rich)
```python
from rich.console import Console
from rich.text import Text

console = Console()
ORANGE = "bold #B44A1A"
console.print(Text("Blackbox Umbra", style=ORANGE))
```

### In Code Comments
```python
# ╔════════════════════════════════════╗
# ║  Blackbox Umbra — Recon Module    ║
# ║  Automated reconnaissance phase    ║
# ╚════════════════════════════════════╝
```

---

## Brand Voice

**Tone:** Professional, authoritative, direct  
**Audience:** OSCP-certified penetration testers, security professionals  
**Key Messages:**
- "Automated discovery saves time"
- "Comprehensive network visibility"
- "Authorized use only"
- "Professional-grade intelligence"

**Example Marketing Copy:**
> Blackbox Umbra automates the reconnaissance phase of penetration testing engagements. From host discovery to vulnerability identification, Umbra delivers comprehensive network intelligence in hours—not days.

---

## Social Media & Sharing

When sharing Blackbox Umbra:

**Twitter/X:**
```
Introducing Blackbox Umbra — our proprietary pentest automation 
framework for reconnaissance & vulnerability discovery. 
"The shadow sees all." 

#InfoSec #PenetrationTesting #BlackboxIntelligence
```

**LinkedIn:**
```
We've built Blackbox Umbra, an automated penetration testing 
framework that can execute comprehensive reconnaissance across 
enterprise networks in hours. 

Available for authorized partners & internal use only.
```

**GitHub Topic Tags:**
- `penetration-testing`
- `security-tools`
- `reconnaissance`
- `vulnerability-scanning`
- `automated-recon`
- `proprietary`
- `no-modifications`

---

## Contact & Brand Questions

**Brand Steward:** Alexander Morrow, CEO  
**Brand Email:** info@blackboxintelgroup.com  
**Website:** https://blackboxintelgroup.com  

For brand guidelines, asset requests, or usage clarification, contact the brand steward.

---

**© 2026 Blackbox Intelligence Group LLC**  
**All Rights Reserved**  
*The shadow sees all.* 🕵️
