---
name: NTIP Operations Console
description: A precise desktop instrument for operating secure NTIP overlays.
---

# Design System: NTIP Operations Console

## Overview

**Creative North Star: "The Calibrated Field Instrument"**

**Approved visual direction:** Direction A, approved 2026-07-20. The permanent
left rail and dense overview are the application shell. Direction B's
deterministic topology treatment and Direction C's ledger density carry into
their respective pages without replacing Direction A's navigation or hierarchy.

The console is a production product surface for a small infrastructure team. It
should feel measured, durable, and immediate on a wide desktop display in both
daylight and a dim incident-response environment. Information density is high,
but grouping, rhythm, and typography keep the operator oriented.

The system rejects generic SaaS admin templates, purple-gradient infrastructure
clichés, glassmorphism, ornamental glow, terminal cosplay, and motion without
operational meaning. Surfaces stay quiet so health, selection, warnings, and
dangerous actions remain unmistakable.

**Key Characteristics:**

- Restrained color strategy with one oxidized-copper action accent.
- System-adaptive light and dark themes with a persistent user override.
- Compact, stable tables and a permanent desktop navigation rail.
- Fine structural borders and tonal layering instead of card grids.
- State transitions only, with reduced-motion parity.

## Colors

Use tinted neutrals as the dominant canvas. Oxidized copper is reserved for
primary actions, current selection, and focus; it occupies no more than ten
percent of a screen. Success, warning, danger, and information use distinct
semantic colors and always pair with text or iconography.

The implemented light canvas is `oklch(0.965 0.004 205)` with an almost-white
surface, `oklch(0.22 0.012 205)` foreground, and `oklch(0.86 0.008 205)` fine
borders. Dark mode uses `oklch(0.165 0.011 205)`,
`oklch(0.91 0.007 205)`, and `oklch(0.31 0.014 205)` respectively. Copper is
`oklch(0.53 0.115 43)` in light mode and `oklch(0.68 0.12 48)` in dark mode.
The light warning foreground is `oklch(0.5 0.12 79)`; its darker lightness is
intentional after automated contrast testing of compact warning badges.
The source of truth, including muted, strong, hover, focus, and semantic
variants, is `apps/dashboard/src/app/globals.css`.

**The Rare Copper Rule.** Copper marks intent, never decoration. Do not use it
for healthy status because selection and success must remain distinct.

## Typography

Use Geist Sans for interface text and Geist Mono for addresses, identifiers,
timestamps, commands, and tabular numerals. The scale is fixed and compact with
clear weight contrast; prose stays within 65 to 75 characters while operational
tables may run wider.

**The Instrument Label Rule.** Monospace is evidence formatting, not an
aesthetic costume. Navigation, buttons, and explanatory copy remain sans-serif.

## Elevation

The system is flat by default. Depth comes from tinted surface layers, fine
borders, and restrained overlays. Shadows appear only where a popover, menu, or
dialog must establish a temporary layer; they remain broad and low contrast.

**The Bench Surface Rule.** If a panel looks like it floats at rest, the shadow
is too strong.

## Components

Use familiar Radix-backed shadcn primitives with consistent compact density.
The owned `packages/ui` source currently provides buttons, inputs, labels,
tables, badges, tabs, menus, selects, switches, alerts, progress, tooltips, and
dialog/alert-dialog primitives. These components cover keyboard focus,
disabled and error behavior without creating a runtime dependency on a hosted
component service. Cards are used only for genuine grouping; nested cards are
forbidden.

Navigation is permanently visible at supported desktop sizes. Below 1024px the
application renders an explicit unsupported-size state rather than a compressed
or partially functional mobile console.

## Mock Fidelity Inventory

The implementation must preserve these visible ingredients from the approved
north-star mock:

- A narrow, permanent dark-toned navigation rail with the NTIP wordmark,
  selected-route copper treatment, lower Settings/System destinations, and a
  compact authenticated-user control.
- A quiet top status bar with UTC time, data freshness, global search, and
  restrained utility controls.
- An overview composed as one continuous instrument surface: a compact summary
  strip, VNR health ledger, restrained operational trend, prioritized events,
  a dense Node table, and recent activity. Fine dividers and spacing establish
  groups instead of repeated floating cards.
- An oxidized-copper focus/action/selection accent used sparingly. Health uses
  separate green, amber, red, and neutral vocabulary with icon or text parity.
- Fixed, compact Geist Sans hierarchy and Geist Mono evidence fields. Tables
  use tabular numerals and stable columns.
- Deterministic topology with Master, VNR, Node, and route relationships,
  pan/zoom, filters, inspector, and a complete accessible table alternative.
- Flat tinted surfaces in both light and dark themes, with overlays as the only
  visibly elevated material and state-only 150 to 200 millisecond motion.

The mock's vendor models, CPU/memory/temperature fields, time-series link-health
chart, and fabricated incident counts are not NTIP contract fields. They must
not appear as fake production data. Real inventory, liveness, session, traffic,
event, audit, connectivity, and freshness fields replace them. Small CSS or SVG
summaries may visualize only values that can be derived honestly from those
responses.

## Implemented Interaction Register

- The protected App Router layout verifies `/auth/me` on the loopback API
  before rendering the permanent rail. Cookie presence alone is never treated
  as authentication.
- Server Components perform initial reads with `no-store`; small Client
  Components perform same-origin mutations and bounded polling. At most two
  background reads run concurrently, polling pauses while hidden or offline,
  intervals jitter, failures back off to 20, 40, then 60 seconds, and the last
  successful result remains visible with an explicit stale state.
- Overview, topology, operational Node views, and active connectivity checks
  refresh every 10 seconds; event/audit activity refreshes every 15 seconds;
  VNR views and session lists refresh every 30 seconds; users/settings refresh
  on focus or mutation.
- The topology is deterministically sorted and laid out in Master, VNR, Node,
  and route columns. It provides filters, pan/zoom, a drill-down inspector, and
  a complete table representation for keyboard and assistive-technology use.
- System, Light, and Dark preferences persist locally. Reduced-motion media
  preferences suppress nonessential transition duration. Below 1024 pixels,
  the application displays a clear unsupported-size message instead of a
  compressed administration surface.
- Production-build Playwright verifies the light and dark overview, keyboard
  topology/table parity, the 1023/1024 guard, and automated WCAG 2.2 AA checks
  for login and authenticated overview surfaces.

## Do's and Don'ts

### Do:

- **Do** make freshness, uncertainty, permission, and pending state explicit.
- **Do** pair every semantic color with readable text and a second visual cue.
- **Do** use deterministic layout, stable columns, and familiar form controls.
- **Do** use opacity and transform transitions lasting roughly 150 to 200ms.
- **Do** keep advanced and destructive actions in dedicated secondary flows.

### Don't:

- **Don't** build a generic SaaS admin template from repetitive metric cards.
- **Don't** use purple gradients, neon-on-black infrastructure clichés, or
  decorative glow.
- **Don't** use glassmorphism, ornamental dashboards, or motion without
  operational meaning.
- **Don't** use terminal cosplay that weakens readable hierarchy or familiar
  controls.
- **Don't** hide destructive behavior, use vague confirmation copy, or rely on
  color-only status.
- **Don't** use gradient text, nested cards, colored side-stripe borders, or
  layout-property animation.
