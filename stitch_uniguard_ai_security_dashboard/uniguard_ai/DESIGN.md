---
name: UNIGUARD AI
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
  on-surface-variant: '#c4c7c8'
  inverse-surface: '#e5e2e1'
  inverse-on-surface: '#313030'
  outline: '#8e9192'
  outline-variant: '#444748'
  surface-tint: '#c6c6c7'
  primary: '#ffffff'
  on-primary: '#2f3131'
  primary-container: '#e2e2e2'
  on-primary-container: '#636565'
  inverse-primary: '#5d5f5f'
  secondary: '#c4c6cf'
  on-secondary: '#2d3137'
  secondary-container: '#43474e'
  on-secondary-container: '#b2b5bd'
  tertiary: '#ffffff'
  on-tertiary: '#342f2d'
  tertiary-container: '#eae1dd'
  on-tertiary-container: '#696360'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#e2e2e2'
  primary-fixed-dim: '#c6c6c7'
  on-primary-fixed: '#1a1c1c'
  on-primary-fixed-variant: '#454747'
  secondary-fixed: '#e0e2eb'
  secondary-fixed-dim: '#c4c6cf'
  on-secondary-fixed: '#181c22'
  on-secondary-fixed-variant: '#43474e'
  tertiary-fixed: '#eae1dd'
  tertiary-fixed-dim: '#cec5c1'
  on-tertiary-fixed: '#1f1b19'
  on-tertiary-fixed-variant: '#4b4643'
  background: '#141313'
  on-background: '#e5e2e1'
  surface-variant: '#353434'
typography:
  display:
    fontFamily: Geist
    fontSize: 48px
    fontWeight: '600'
    lineHeight: '1.1'
    letterSpacing: -0.04em
  headline-lg:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '500'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '500'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Geist
    fontSize: 20px
    fontWeight: '500'
    lineHeight: '1.4'
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Geist
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.6'
    letterSpacing: '0'
  body-md:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: '0'
  label-mono:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '500'
    lineHeight: '1'
    letterSpacing: 0.05em
  caption:
    fontFamily: Geist
    fontSize: 11px
    fontWeight: '400'
    lineHeight: '1.4'
    letterSpacing: '0'
spacing:
  unit: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 40px
  gutter: 16px
  margin-mobile: 16px
  margin-desktop: 32px
---

## Brand & Style

The design system is engineered for high-stakes enterprise cybersecurity environments where clarity, speed of cognition, and professional authority are paramount. It adopts an **Experimental Ultra-Minimalist** aesthetic that moves away from traditional "cyber" tropes—eschewing neon glows and HUD-style clutter in favor of a sophisticated, code-like editorial atmosphere.

The brand personality is silent, precise, and absolute. It seeks to evoke a sense of calm control amidst complex data landscapes. By utilizing the **Geist** typeface, the UI feels like a high-end developer tool merged with a premium broadsheet. The target audience is Security Operations Center (SOC) analysts and C-suite executives who require a noise-free interface that prioritizes signal over decoration.

## Colors

The palette is strictly monochrome to enforce a rigorous information hierarchy, utilizing color only as a functional tool for status communication. 

- **Monochrome Foundation:** The primary interface is built on `#0D0E10`. Text defaults to `#F2F2F2` for maximum legibility, while `#9699A1` is reserved for metadata and de-emphasized labels.
- **Surface Strategy:** We use three distinct shades of black to create structural depth without relying on shadows.
- **Semantic Utility:** Semantic colors (Success, Warning, Critical) are applied with restraint—typically limited to status pips, thin borders, or small text strings—to ensure they immediately draw the eye when an anomaly occurs. 
- **Borders:** A single, consistent border color (`#2A2B30`) defines the grid and separates functional zones.

## Typography

This design system leverages the **Geist** typeface to achieve a technical, Swiss-style editorial layout. 

- **Scale:** High contrast between display sizes and body text creates a clear path for the eye. 
- **Technical Detail:** `label-mono` uses Geist’s clean metrics to present system metadata and timestamps, mimicking a terminal environment. 
- **Rhythm:** Line heights are generous for body text to maintain readability in data-heavy screens, but tighter for display headers to maintain a "locked-in" architectural feel.
- **Alignment:** All text should align to a strict baseline grid to reinforce the sense of mathematical precision.

## Layout & Spacing

The layout philosophy is a **Fixed 12-Column Grid** for desktop, prioritizing "Information Density without Clutter."

- **Modular Grid:** All components and containers must align to a 4px base unit. 
- **The "Silent" Margin:** Use expansive outer margins (`32px`+) on high-level dashboards to create a premium, gallery-like feel.
- **Data Densities:** In the SOC views (tables, logs), padding is reduced to `8px` (sm) to maximize visible telemetry. In settings or profile views, padding increases to `24px` (lg) to promote focus.
- **Responsiveness:** On mobile, the grid collapses to 4 columns with `16px` margins. Large headlines should scale down to their `-mobile` variants to ensure text does not wrap awkwardly.

## Elevation & Depth

This design system rejects shadows in favor of **Tonal Layering** and **Subtle Outlines**.

- **Level 0 (Base):** `#050505` (Surface-dim) – Used for the primary background of the application.
- **Level 1 (Containers):** `#0D0E10` (Surface) – Used for the primary content cards and panels.
- **Level 2 (Interactive/Overlay):** `#1A1B1F` (Surface-bright) – Used for tooltips, dropdown menus, and hovered states.
- **Borders:** Every container is defined by a `1px` solid border of `#2A2B30`. No blurs or gradients are permitted. This creates a "blueprint" aesthetic where the structure is the decoration.

## Shapes

The design system utilizes **Sharp (0px)** roundedness. 

Every element—from primary action buttons to complex data cards and input fields—features hard 90-degree corners. This choice reinforces the brutalist, industrial nature of the cybersecurity platform. It communicates a lack of "softness" and an emphasis on efficiency and structural integrity. 

- **Exceptions:** None. All containers, buttons, pips, and selections must remain strictly rectangular.

## Components

- **Buttons:** 
  - *Primary:* Solid White (`#F2F2F2`) background with Black (`#0D0E10`) text. No border.
  - *Secondary:* Transparent background with a `1px` border of `#2A2B30`. White text.
  - *Ghost:* Transparent background, Gray (`#9699A1`) text.
- **Inputs:** Background uses `Surface-dim`. 1px border. Focus state is indicated by the border changing to White (`#F2F2F2`). Labels are always `label-mono` and positioned above the field.
- **Chips/Status Pips:** Small rectangular blocks. For status, use a 4x4px square of the semantic color followed by `label-mono` text.
- **Data Tables:** No vertical dividers. Horizontal dividers only using `1px` `#2A2B30`. Header row uses `Surface-bright` background and all-caps mono labels.
- **Cards:** No shadow. Background is `Surface`. A `1px` border defines the perimeter. Internal sections are separated by the same border color.
- **Checkboxes/Radios:** Pure geometric shapes. Checkboxes are squares; Radios are squares with a smaller nested square when selected (no circles).