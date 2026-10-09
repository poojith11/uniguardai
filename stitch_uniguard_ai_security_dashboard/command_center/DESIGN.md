---
name: Command Center
colors:
  surface: '#051424'
  surface-dim: '#051424'
  surface-bright: '#2c3a4c'
  surface-container-lowest: '#010f1f'
  surface-container-low: '#0d1c2d'
  surface-container: '#122131'
  surface-container-high: '#1c2b3c'
  surface-container-highest: '#273647'
  on-surface: '#d4e4fa'
  on-surface-variant: '#bac9cc'
  inverse-surface: '#d4e4fa'
  inverse-on-surface: '#233143'
  outline: '#849396'
  outline-variant: '#3b494c'
  surface-tint: '#00daf3'
  primary: '#c3f5ff'
  on-primary: '#00363d'
  primary-container: '#00e5ff'
  on-primary-container: '#00626e'
  inverse-primary: '#006875'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#ffe7e5'
  on-tertiary: '#68000a'
  tertiary-container: '#ffc1bc'
  on-tertiary-container: '#b1121f'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#9cf0ff'
  primary-fixed-dim: '#00daf3'
  on-primary-fixed: '#001f24'
  on-primary-fixed-variant: '#004f58'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#ffdad7'
  tertiary-fixed-dim: '#ffb3ad'
  on-tertiary-fixed: '#410004'
  on-tertiary-fixed-variant: '#930013'
  background: '#051424'
  on-background: '#d4e4fa'
  surface-variant: '#273647'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  body-base:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: 0em
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: 0em
  label-caps:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  container-padding: 24px
  gutter: 16px
  component-gap: 12px
  section-margin: 32px
---

## Brand & Style

The design system is engineered for **UNIGUARD AI**, a high-stakes cybersecurity platform providing "Passive Threat Intelligence." The brand persona is authoritative, precise, and institutional—evoking the atmosphere of a government-grade intelligence hub rather than a consumer tool. 

The visual style is **Technical Minimalism**. It prioritizes high information density and "Explainable AI" by using visual evidence components that distill complex data into actionable insights. The interface avoids unnecessary decorative elements, focusing instead on clarity, speed, and structural integrity. Every pixel must justify its presence, creating a environment that feels secure, responsive, and intellectually rigorous.

## Colors

The color palette is designed for prolonged operation in dark environments, reducing eye strain while highlighting critical data points.

- **Foundations:** The background uses a near-black `#0a0b0d` to provide infinite depth, while surfaces utilize `#16181d` to define functional zones.
- **Accents:** The primary seed color `#00e5ff` is reserved for active states, interactive elements, and primary data threads. 
- **Semantic Logic:** Status indicators follow a strict hierarchy: Emerald Green for verified safety, Amber for anomalies requiring investigation, and Ruby Red for active breaches. 
- **Typography:** Pure White is used for primary headers and critical values, while Cool Gray handles metadata and secondary labels to maintain a clear visual hierarchy.

## Typography

This design system utilizes **Inter** for its exceptional legibility at small sizes and neutral, functional character. To reinforce the technical nature of "Explainable AI," **JetBrains Mono** (or a system monospaced font) is introduced for technical data strings, IP addresses, and log outputs.

- **Headlines:** Use tight letter-spacing and semi-bold weights to convey authority.
- **Data Display:** Technical values should always use the monospaced variable to ensure alignment in dense tables.
- **Labels:** Small, uppercase labels with increased tracking are used for categorizing metadata and table headers, ensuring they remain distinct from interactive content.

## Layout & Spacing

The layout employs a **Fluid Grid System** designed for information-dense dashboards. It utilizes a 12-column grid on desktop to allow for flexible arrangements of charts, logs, and maps.

- **Rhythm:** A strict 4px base unit governs all spacing.
- **Density:** Padding within cards and tables is kept compact (12px to 16px) to maximize the "at-a-glance" intelligence available to the operator.
- **Breakpoints:** 
  - **Desktop (1440px+):** 12 columns, 24px margins.
  - **Tablet (768px-1439px):** 6 columns, 16px margins.
  - **Mobile (<767px):** 2 columns, 12px margins, cards stack vertically.

## Elevation & Depth

In a dark, technical environment, depth is communicated through **Tonal Layering** and **Low-Contrast Outlines** rather than heavy shadows.

- **Surfaces:** There are three levels of depth. Level 0 is the background (`#0a0b0d`). Level 1 is the primary card surface (`#16181d`). Level 2 is used for hovered states or nested elements (`#1f2229`).
- **Borders:** Every interactive surface features a subtle 1px border using `#2d3139`. This "ghost border" provides structure without adding visual noise.
- **Active Glow:** Primary interactive elements (like active tabs or critical alerts) may use a subtle outer glow of the primary color (`#00e5ff`) with 15% opacity to indicate focus or urgency.

## Shapes

The shape language is **Soft (Level 1)**. The 0.25rem (4px) corner radius provides a modern, professional feel that is more approachable than sharp 90-degree angles but maintains a disciplined, institutional structure.

- **Standard Elements:** Buttons, inputs, and small widgets use `rounded` (4px).
- **Containers:** Larger dashboard cards and main navigation panels use `rounded-lg` (8px).
- **Status Pills:** Small indicators for "Online" or "Threat Level" use `rounded-xl` (12px) or full pill shapes to distinguish them from structural elements.

## Components

- **Buttons:** Primary buttons use a solid `#00e5ff` fill with black text for maximum contrast. Secondary buttons use the ghost border style with cyan text.
- **Technical Cards:** Feature a header row with a `label-caps` title and an optional monospaced "ID" tag. Borders are mandatory.
- **Data Tables:** High-density with no vertical lines. Horizontal dividers use `#2d3139`. Row hover states should use Surface Level 2.
- **Status Indicators:** Small, circular dots paired with monospaced text. For "Critical" states, the text should also inherit the Ruby Red color.
- **Visual Evidence Components:** Specialized widgets that show "Why" the AI made a decision. These use small sparklines, confidence percentage gauges, and highlighted monospaced log snippets.
- **Inputs:** Dark backgrounds (`#0a0b0d`) with a subtle border. On focus, the border transitions to the Primary Cyan with a 1px solid stroke.