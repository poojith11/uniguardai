---
name: Institutional Intelligence
colors:
  surface: '#fdf8f8'
  surface-dim: '#ddd9d8'
  surface-bright: '#fdf8f8'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f7f3f2'
  surface-container: '#f1edec'
  surface-container-high: '#ebe7e6'
  surface-container-highest: '#e5e2e1'
  on-surface: '#1c1b1b'
  on-surface-variant: '#444748'
  inverse-surface: '#313030'
  inverse-on-surface: '#f4f0ef'
  outline: '#747878'
  outline-variant: '#c4c7c7'
  surface-tint: '#5f5e5e'
  primary: '#000000'
  on-primary: '#ffffff'
  primary-container: '#1c1b1b'
  on-primary-container: '#858383'
  inverse-primary: '#c8c6c5'
  secondary: '#5e5e5e'
  on-secondary: '#ffffff'
  secondary-container: '#e1dfdf'
  on-secondary-container: '#626262'
  tertiary: '#000000'
  on-tertiary: '#ffffff'
  tertiary-container: '#1d1b1a'
  on-tertiary-container: '#868381'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#e5e2e1'
  primary-fixed-dim: '#c8c6c5'
  on-primary-fixed: '#1c1b1b'
  on-primary-fixed-variant: '#474646'
  secondary-fixed: '#e4e2e2'
  secondary-fixed-dim: '#c7c6c6'
  on-secondary-fixed: '#1b1c1c'
  on-secondary-fixed-variant: '#464747'
  tertiary-fixed: '#e6e1df'
  tertiary-fixed-dim: '#cac6c3'
  on-tertiary-fixed: '#1d1b1a'
  on-tertiary-fixed-variant: '#484645'
  background: '#fdf8f8'
  on-background: '#1c1b1b'
  surface-variant: '#e5e2e1'
typography:
  headline-xl:
    fontFamily: Inter
    fontSize: 48px
    fontWeight: '700'
    lineHeight: '1.1'
    letterSpacing: -0.04em
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.3'
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: '1.6'
    letterSpacing: '0'
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: '0'
  label-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '600'
    lineHeight: '1'
    letterSpacing: 0.05em
  mono-technical:
    fontFamily: monospace
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: '0'
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  gutter: 24px
  margin-desktop: 64px
  margin-mobile: 16px
  stack-sm: 8px
  stack-md: 16px
  stack-lg: 32px
---

## Brand & Style

This design system is built upon the principles of **Institutional Minimalism**. It rejects the high-friction, neon-soaked aesthetics common in cybersecurity in favor of a "Silent Sentinel" approach. The brand personality is authoritative, calm, and hyper-organized, designed to evoke a sense of absolute control and clarity for cybersecurity analysts.

The visual style leverages a premium monochrome palette to reduce cognitive load. It draws from modern editorial design—emphasizing whitespace, precise alignment, and a sophisticated interplay between warm-toned backgrounds and stark white surfaces. The goal is to transform complex threat data into a legible, premium experience that feels more like a high-end financial report than a technical console.

## Colors

The palette is strictly functional and restrained. By utilizing a monochrome foundation, color is reserved exclusively for state and priority signaling, ensuring that critical alerts are never lost in a "loud" UI.

- **Primary & Action:** Black (`#111111`) is used for primary brand elements and high-priority interactions.
- **Secondary:** A muted slate gray (`#6B6B6B`) provides hierarchy for metadata and de-emphasized UI elements.
- **Surface & Background:** The core experience lives on a warm off-white (`#FAFAF8`), while interactive modules and cards use pure white (`#FFFFFF`) to create a subtle "lift" without relying on heavy shadows.
- **Semantic Accents:** Status colors (Green, Amber, Red) are desaturated and "dusty" to maintain the sophisticated, high-end editorial feel while still providing necessary visual cues for threat levels.

## Typography

This design system utilizes **Inter** for its systematic, utilitarian clarity. The typographic hierarchy is driven by extreme contrast in weight and letter spacing rather than variety in typeface.

- **Editorial Headings:** Large headlines use tight letter spacing and heavy weights to create a sense of presence and institutional authority.
- **Technical Readouts:** For IP addresses, hash codes, and logs, a monospaced font is used to provide the necessary precision for technical analysis.
- **Labels:** Micro-copy and status labels use increased letter spacing and uppercase styling to ensure legibility at small scales without cluttering the visual field.

## Layout & Spacing

The layout philosophy follows a **Disciplined Fluidity**. It uses a 12-column grid for desktop views with generous margins to frame the content like a premium publication.

- **Vertical Rhythm:** A strict 4px baseline grid ensures consistent alignment of text and components.
- **Negative Space:** Whitespace is treated as a functional element to separate disparate data streams. Large sections are separated by `32px` or `48px` to allow the eye to rest.
- **Reflow:** On mobile devices, the 12-column grid collapses to a single column, with margins reducing to `16px`. Data-heavy tables should transition to card-based summaries to maintain readability.

## Elevation & Depth

Depth in this design system is conveyed through **Tonal Separation** and **Micro-Shadows**. It avoids the floating appearance of traditional Material Design in favor of a grounded, layered aesthetic.

- **Base Layer:** The primary background (`#FAFAF8`).
- **Surface Layer:** Cards and containers (`#FFFFFF`) sit on the base. They are defined by a `1px` border in `#E5E5E5`.
- **Shadows:** Only the top-level surfaces (like modals or dropdowns) use shadows. These shadows are extremely diffused, using a low-opacity black (`rgba(0,0,0,0.04)`) with a high blur radius to create a soft "glow" rather than a hard drop shadow.
- **Interactions:** Hover states on cards should not lift the element; instead, the border should darken slightly to `#D1D1D1` to indicate interactivity while maintaining the flat, institutional structural integrity.

## Shapes

The shape language is conservative and precise. 

- **Softness:** A `0.25rem` (4px) radius is the standard for buttons, input fields, and small containers. This provides a subtle "human" touch without sacrificing the professional, rigorous feel of the platform.
- **Large Surfaces:** Containers and cards use a slightly larger `0.5rem` radius to softly frame large blocks of information.
- **Strictness:** Square corners are avoided entirely to prevent the UI from feeling aggressive or dated, but radii never exceed what is necessary to "soften" the edge.

## Components

### Buttons
- **Primary:** Solid `#111111` background with white text. No gradients.
- **Secondary:** Ghost style with `#E5E5E5` border and `#111111` text.
- **Tertiary:** Text-only with an underline on hover for navigational links.

### Input Fields
- Understated design: `1px` border in `#E5E5E5`, pure white background. Focus state changes border to `#111111` with no outer glow.

### Cards & Modules
- Used to group threat intelligence data. Each card must have a clear `label-sm` header. The border is mandatory to separate white surfaces from the warm-white background.

### Status Chips
- Small, pill-shaped indicators. Use a light tinted background of the status color (e.g., 10% opacity) with the full-strength color for the text and a small leading dot.

### Data Tables
- Minimalist rows separated by `1px` horizontal lines. No vertical lines. Header row uses `label-sm` typography with a subtle background tint of `#F4F4F2`.

### Threat Indicators
- Distinctive, custom-designed icons for "Healthy," "Suspicious," and "Critical" that rely on geometric clarity rather than complex illustrations.