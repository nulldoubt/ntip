# Product

## Register

product

## Users

NTIP is operated by small, trusted infrastructure and security teams managing a
self-hosted Master and a typical fleet of 10 to 250 Nodes. Operators use a wide
desktop display for routine administration and incident triage, sometimes in a
dim environment and under time pressure. They need to understand degraded
state quickly, make deliberate topology changes, and leave an accountable
record of sensitive actions.

## Product Purpose

NTIP connects, manages, observes, and troubleshoots distributed Nodes behind
NAT through a secure Master-mediated overlay. The management surface makes the
existing VNR, Node, route, enrollment, runtime, and security model legible
without weakening the protocol boundary. Success means an operator can answer
what is configured, what is currently reachable, what changed, and what safe
action to take next without resorting to undocumented state or guesswork.

## Brand Personality

Precise, calm, trustworthy. The product should feel like a well-made measuring
instrument: dense enough for experts, restrained enough for long sessions, and
explicit whenever an action changes security or connectivity. Copy is direct,
technical, and free of marketing language.

## Anti-references

- Generic SaaS admin templates built from repetitive metric cards.
- Purple gradients, neon-on-black infrastructure clichés, or decorative glow.
- Glassmorphism, ornamental dashboards, and motion without operational meaning.
- Terminal cosplay that sacrifices readable hierarchy or familiar controls.
- Hidden destructive behavior, vague confirmation copy, and color-only status.

## Design Principles

1. **State before spectacle.** Current health, freshness, and uncertainty are
   always easier to see than decoration.
2. **Progressive operational depth.** Common reads and safe actions are direct;
   advanced and dangerous operations remain one intentional level deeper.
3. **One source of truth.** UI language and behavior follow NTIP's VNR, Node,
   route, enrollment, and generation semantics instead of inventing a parallel
   model.
4. **Safety is visible.** Preconditions, permissions, reauthentication, audit,
   and irreversible consequences are explained at the point of action.
5. **Expert density with earned familiarity.** Tables, navigation, forms, and
   feedback use predictable product patterns and remain keyboard efficient.

## Accessibility & Inclusion

Target WCAG 2.2 AA. Every workflow must be keyboard operable with visible focus,
semantic landmarks, associated form labels, and announced asynchronous state.
Status combines text with icon or shape and never relies on color alone. Honor
reduced-motion and system color-scheme preferences. Provide a table equivalent
for topology and a clear unsupported-size state below the 1024px desktop floor.
