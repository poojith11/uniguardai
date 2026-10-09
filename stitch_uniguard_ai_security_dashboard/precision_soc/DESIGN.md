---
name: Precision SOC
colors:
  surface: '#141313'
  surface-dim: '#141313'
  surface-bright: '#3a3939'
  surface-container-lowest: '#0e0e0e'
  surface-container-low: '#1c1b1b'
  surface-container: '#201f1f'
  surface-container-high: '#2a2a2a'
  surface-container-highest: '#353434'
  on-surface: '#e5e2e1'
  on-surface-variant: '#c6c6ca'
  inverse-surface: '#e5e2e1'
  inverse-on-surface: '#313030'
  outline: '#909094'
  outline-variant: '#45474a'
  surface-tint: '#c7c6c9'
  primary: '#c7c6c9'
  on-primary: '#303033'
  primary-container: '#0d0e10'
  on-primary-container: '#7b7b7d'
  inverse-primary: '#5e5e61'
  secondary: '#c7c6ca'
  on-secondary: '#2f3033'
  secondary-container: '#46464a'
  on-secondary-container: '#b5b4b8'
  tertiary: '#cec5c1'
  on-tertiary: '#352f2d'
  tertiary-container: '#110d0b'
  on-tertiary-container: '#817a76'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#e3e2e5'
  primary-fixed-dim: '#c7c6c9'
  on-primary-fixed: '#1b1c1e'
  on-primary-fixed-variant: '#464749'
  secondary-fixed: '#e3e2e6'
  secondary-fixed-dim: '#c7c6ca'
  on-secondary-fixed: '#1b1b1f'
  on-secondary-fixed-variant: '#46464a'
  tertiary-fixed: '#ebe0dc'
  tertiary-fixed-dim: '#cec5c1'
  on-tertiary-fixed: '#1f1b18'
  on-tertiary-fixed-variant: '#4c4543'
  background: '#141313'
  on-background: '#e5e2e1'
  surface-variant: '#353434'
typography:
  headline-lg:
    fontFamily: IBM Plex Sans
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: IBM Plex Sans
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: IBM Plex Sans
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  body-lg:
    fontFamily: JetBrains Mono
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  data-value:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 16px
  label-caps:
    fontFamily: IBM Plex Sans
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.08em
spacing:
  unit: 4px
  container-padding: 24px
  gutter: 16px
  component-gap-sm: 8px
  component-gap-md: 16px
---

## Brand & Style

This design system is built for mission-critical Security Operations Centers where clarity and speed of cognition are paramount. The visual narrative moves away from "cyber-glamour" toward a **strictly technical, brutalist-lite aesthetic**. It prioritizes high-density data visualization and rapid incident response through a high-precision, developer-centric interface.

The brand personality is **stoic, expert, and transparent**. It avoids all decorative flourishes, neon glows, and rounded abstractions in favor of hard edges, monospaced data fields, and a monochromatic foundation. The intent is to lower cognitive load, allowing the user to focus exclusively on anomalies and threats signaled by the strategic use of status colors.

## Colors

The palette is engineered for prolonged usage in dark-room SOC environments. It follows a **monochrome-first logic**, where the UI chrome and background are virtually indistinguishable in saturation, ensuring that color is only perceived when it represents a functional state or a security threat.

- **Foundational Neutrals:** Use `#0D0E10` for global backgrounds. Use `#151619` for secondary navigation and `#1A1B1F` for interactive surfaces and card containers.
- **Borders:** Use `#2A2B30` for all structural dividers. Borders are the primary method of separation in this design system.
- **Semantic Accents:** Use status colors sparingly. For example, a "Critical" alert should utilize a 2px left border or a small indicator dot rather than a full-surface flood.

## Typography

This design system utilizes a dual-font strategy to differentiate between **interface guidance** and **raw data**.

- **Interface Logic (IBM Plex Sans):** Used for headlines, navigation links, and structural labels. It provides a professional, authoritative tone that is easy to scan.
- **Data Integrity (JetBrains Mono):** Used for all dynamic values, IP addresses, timestamps, and logs. The monospaced nature ensures that columns of data align perfectly, facilitating rapid pattern recognition and vertical scanning of security logs.

Large headlines (above 24px) should reduce their tracking by -1% to maintain a compact, "architectural" feel.

## Layout & Spacing

The layout is governed by a **fixed 12-column grid** on desktop and a **fluid 4-column grid** on mobile. The grid emphasizes horizontal alignment and strict containment.

- **Rhythm:** All spacing must be multiples of 4px. Use 16px for standard gutters between dashboard widgets.
- **Whitespace:** Use generous margins (24px - 32px) around the primary workspace to prevent the "technical" nature of the design from feeling cluttered.
- **Structure:** Content is organized into "Panes" rather than floating windows. Panes are separated by 1px borders (#2A2B30) without gaps, mimicking a professional hardware terminal.

## Elevation & Depth

This design system rejects the use of shadows and blurs. Depth is communicated via **Tonal Layering and Borders**.

- **Z-Index Strategy:**
    - **Level 0 (Background):** #0D0E10.
    - **Level 1 (Sidebars/Nav):** #151619.
    - **Level 2 (Dashboard Cards):** #1A1B1F with a 1px border of #2A2B30.
    - **Level 3 (Modals/Popovers):** Same as Level 2 but with a slightly higher contrast border (#3F4045) to indicate focus.

Instead of shadows, use a 1px solid border for all containers. For active or focused states, increase the border brightness or change the border color to the primary status color (e.g., Warning).

## Shapes

The design system employs a **zero-radius (sharp corner) philosophy**. Every button, card, input field, and modal has a corner radius of `0`.

This sharp geometry reinforces the "Precision Tool" metaphor. It suggests a rigid, uncompromising environment suitable for high-stakes security monitoring. Visual interest is generated through the interplay of lines and typography rather than soft shapes.

## Components

### Buttons
Buttons are strictly rectangular.
- **Primary:** Solid `#F2F2F2` background with `#0D0E10` text.
- **Secondary:** Transparent background with a 1px `#2A2B30` border.
- **Danger:** Transparent background with a 1px `#EF5350` border and text.

### Alert Cards
Alert cards are the core component of the SOC.
- **Container:** `#1A1B1F` background, `#2A2B30` border.
- **Severity Indicator:** A 4px vertical bar on the extreme left edge of the card using the semantic status color.
- **Metadata:** All data (IPs, Hash IDs) must use `JetBrains Mono` at 13px. Labels for metadata must use `IBM Plex Sans` uppercase at 11px.

### Inputs & Selects
- Background: `#0D0E10`.
- Border: 1px `#2A2B30`.
- On Focus: Border color changes to `#9699A1`.
- Text: Always `JetBrains Mono` for consistency with technical data entry.

### Charts & Monitoring
- **Axes:** Use `#2A2B30` for grid lines. 
- **Data Lines:** Use thin 1.5px strokes. Avoid area fills unless the opacity is below 10%.
- **Colors:** Use the Neutral Gray for baseline data; only use Success/Warning/Critical colors for trendlines that cross specific thresholds.

### Sidebar
- **Background:** `#151619`.
- **Icons:** 20px monochrome line icons. Active states should be indicated by a high-contrast white icon and a simple 2px vertical highlight on the left.