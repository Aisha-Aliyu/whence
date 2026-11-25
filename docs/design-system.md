# Design system

How Whence looks and behaves on screen. Components use the tokens in [design/tokens.css](../design/tokens.css) and never raw colors, sizes or font names. The web app copies that file on Day 7.

| File | What it holds |
| --- | --- |
| `design/tokens.css` | Color, type, space, shape, size and motion tokens, for light and dark mode |
| `design/logo.svg` | The mark: two brackets around a dot, a citation around its source |
| `design/favicon.svg` | The mark on a tile, with its own dark mode |
| `design/icons.svg` | Our eight icons as one sprite |
| `design/wireframes/` | Sign in, asking a question, and documents |

## Color

The palette comes from the product spec: ink #11141B, signal blue #0245CF and paper #EDEDED. Blue marks what you can act on: buttons, links, citations and the focus ring. Everything else stays ink and paper.

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `--color-bg` | #EDEDED | #11141B | Page background |
| `--color-surface` | #FFFFFF | #1B1F29 | Panels, inputs, tables |
| `--color-surface-muted` | #E2E3E6 | #262B37 | Table headers, skeletons |
| `--color-text` | #11141B | #EDEDED | Text |
| `--color-text-muted` | #4B5160 | #A7ADB9 | Secondary text |
| `--color-accent` | #0245CF | #8AAEFF | Actions, links, citations, focus |
| `--color-accent-strong` | #01358F | #B3CBFF | Hover and pressed |
| `--color-on-accent` | #FFFFFF | #11141B | Text on accent buttons |
| `--color-border` | #7A808C | #6E7584 | Input and button borders |
| `--color-divider` | #D3D5DA | #2F3542 | Decorative lines only |
| `--color-danger` | #B42318 | #FF9A8F | Errors |
| `--color-success` | #0A6B3B | #6FD39C | Confirmations |
| `--color-highlight` | #D9E3F8 | #24345A | The cited passage |

Dark mode cannot reuse signal blue for text: it is 2.4:1 on ink. It uses a lighter blue instead.

### Contrast

Calculated with the WCAG 2.2 formula. Text needs 4.5:1, and borders, icons and focus rings need 3:1.

| Pair | Light | Dark |
| --- | --- | --- |
| Text on page, panel | 15.7, 18.4 | 15.7, 14.1 |
| Muted text on page, panel | 6.8, 7.9 | 8.2, 7.3 |
| Accent on page, panel | 6.5, 7.6 | 8.4, 7.5 |
| Button text on accent, on hover | 7.6, 11.0 | 8.4, 11.3 |
| Danger on page, panel | 5.6, 6.6 | 9.0, 8.1 |
| Success on page, panel | 5.6, 6.6 | 10.1, 9.0 |
| Text, muted, accent on highlight | 14.3, 6.2, 5.9 | 10.5, 5.4, 5.6 |
| Border on page, panel | 3.4, 4.0 | 4.0, 3.6 |

Color never carries meaning alone (WCAG 1.4.1). An error shows the alert icon and words, and a status says "Ready" or "Failed" in text.

## Type

IBM Plex Sans for the interface and for reading, and IBM Plex Mono for citation numbers, page numbers and IDs. Decided on Day 3 for three reasons: both are under the SIL Open Font License ([license](https://github.com/IBM/plex/blob/master/LICENSE.txt)), so we can serve them from our own domain with no font service seeing our users; Plex Mono tells I, l and 1 apart, and 0 and O, which matters in the page numbers and IDs we set in it; and the sans and mono share one design, so citations sit calmly inside a sentence. We load four files: Sans 400, 500 and 600, and Mono 400.

| Token | Size | Use |
| --- | --- | --- |
| `--text-sm` | 14px | Captions, table details |
| `--text-base` | 16px | Body text and controls. Nothing a user must read goes smaller than 14px |
| `--text-lg` | 18px | Answers |
| `--text-xl` | 20px | Section headings |
| `--text-2xl` | 24px | Page titles |
| `--text-3xl` | 32px | Headings on the public site |

Line height is 1.5 for interface text and 1.65 for answers. Reading text stops at 70 characters a line (`--measure`). Sizes are in rem, so they follow the user's browser text size.

## Space, shape and size

- Space follows a 4px grid: 4, 8, 12, 16, 24, 32, 48 and 64px.
- Corners: 4px for buttons, inputs and citation chips, 8px for panels, menus and dialogs. Nothing rounder, so no pill shapes.
- Panels are separated by color and borders. Only menus and dialogs, which float over the page, get a shadow.
- Tap targets are at least 44 by 44px wherever the layout allows, and never under 24 by 24px.
- Layout works from 280px to 2560px wide. Breakpoints at 640px (phone to tablet) and 1024px (side panels appear). Content stops widening at 1440px.

## Motion and focus

- Motion only shows a change of state, such as a panel opening, and lasts 150ms. It turns off when the user asks for reduced motion.
- Every focusable element shows a 2px solid accent outline, 2px away from its edge. We never remove it.

## Components

- Buttons. Primary: accent background with on-accent text, one per view. Secondary: panel background, border and text color. Quiet: accent text, underlined. Hover and press darken to the strong accent, with no fading. A busy button keeps its label and gains a spinner.
- Inputs. A visible label above every input, never a placeholder in its place. Errors appear under the field in the danger color, with the alert icon and words, and are linked to the input with `aria-describedby`.
- Citations. A small mono number in a bordered chip, right after the sentence it supports. It is a button whose name gives the source, such as "Source 1, Billing policy.pdf, page 4". It opens the source viewer, which highlights the passage. Closing the viewer returns focus to the chip.
- Answers. Text streams in. When no passage supports an answer, Whence says the documents do not cover the question, in plain words, with no citation.
- Messages. Every action ends with a success or error message. Short confirmations use `role="status"`, errors use `role="alert"`, and errors that need a fix stay on the page next to the field or row.
- Loading. Skeletons match the final layout block for block. They do not shimmer.
- Empty states. One sentence that says what goes here, and the one button that adds it.
- Icons. Our own, from `design/icons.svg`: 24px grid, 1.75px stroke, drawn in the text color. An icon always has a visible label, or its button has an `aria-label`.
- Logo. The mark is two brackets around a dot: a citation around its source. Next to it, "Whence" is set in Plex Sans 600. Keep clear space equal to the dot's width, and do not use the mark under 16px.
- Theme. The app follows the system setting, and a setting lets each user force light or dark.

None of the patterns in CLAUDE.md's UI rules appear here: no gradients, glass effects, pill buttons, cursor effects, fade-in on scroll, emojis or stock photos.

## Screens

The wireframes cover the three screens the rest are built from:

- [Sign in](../design/wireframes/sign-in.svg), at phone width.
- [Asking a question](../design/wireframes/ask.svg), with an answer, citations and the source viewer.
- [Documents](../design/wireframes/documents.svg), with every status a file can have.

Sign-up, two-factor, members and settings reuse these layouts. Each screen gets its final design in the pull request that builds it, on Day 7.
