# Translating the NetBird UI

A short brief for translating the desktop UI — for any translator, human or AI agent (*"you"* = whoever's translating).

**Drive an agent with:** *"Read `i18n/TRANSLATING.md` and translate the UI to Russian"* — or *"…and review the existing German translation."*

> 💡 **The one habit that matters most:** read each key's `description` before translating it. Labels are terse and ambiguous on their own; the `description` tells you what the string is, where it shows up, what to keep verbatim, and what it actually means.

---

## What NetBird is

A **business zero-trust VPN** — an encrypted **overlay mesh** between a company's devices, built on **WireGuard®**, connecting peers directly with a **relay** fallback. This is the **desktop client** (tray app + windows) someone runs to connect, switch profiles, browse peers, and pick an exit node — *not* the admin dashboard.

**Audience:** IT-literate professionals. **Tone:** clear and professional, never consumer-cute.

**The vocabulary you'll meet:**

| Term | What it means here |
|---|---|
| **Peer** | A device on the network (laptop, server, phone) |
| **Resource / Network** | A routed network or service reachable through NetBird (UI calls these "Resources") |
| **Exit Node** | A peer that routes *all* internet traffic, like a full-tunnel gateway |
| **Profile** | A saved connection identity you can switch between |
| **Daemon** | The background service the UI talks to |
| **Management server** | The control plane — *Cloud* (hosted) or *self-hosted* (customer-run) |
| **Relay** | Forwards traffic when two peers can't connect directly |
| **Rosenpass** | Post-quantum security layered over WireGuard® |
| **Handshake** | The periodic WireGuard® key sync between peers |

---

## The files

```
i18n/locales/_index.json         shipped-language list
i18n/locales/en/common.json      source of truth — message + description
i18n/locales/<code>/common.json  a target — message only
```

Chrome-extension JSON, each key → `{ "message", "description" }`. You translate the **`message`**.

| ✅ Do | ❌ Don't |
|---|---|
| Keep **every key** from `en`, in the same order | Translate, rename, reorder, drop, or add keys (they're identifiers; the set grows over time) |
| Put **only `message`** in target bundles | Copy `description` into a target bundle |
| Give every key a non-empty `message` | Leave keys missing or empty |
| Save valid UTF-8 JSON, no BOM | Add trailing commas or break the JSON |

---

## Hard rules — get these exactly right

These are the usual ways a translation *breaks the app*, not just reads oddly.

| ✅ Do | ❌ Don't |
|---|---|
| Copy `{placeholders}` verbatim — `{version}`, `{count}`, `{name}`… | Translate the word inside the braces (`{verbleibend}` breaks it) |
| Reposition a placeholder so the sentence flows | Drop or duplicate a placeholder |
| Preserve every `\n`, leading/trailing space, and trailing `...` | Trim "invisible" spaces or the `...` (they're load-bearing) |
| Keep `®` in WireGuard® and quotes around `{name}` | Strip punctuation the description flags |

**Plurals:** the app has only a *one / other* split — the singular key fires only when `count == 1`; the `{count}` key covers everything else (0, 2, 5, 100…). Languages with more than two forms (ru, pl, uk) can't be fully correct here — use the form that fits the widest range (Russian genitive plural: `минут` / `часов` / `дней`). Don't invent extra keys or cram multiple forms into one string. When no single form fits every value — a unit label after a number field, say — reach for a number-agnostic form (an abbreviation, or wording that reads the same for 1 and 100) instead of forcing a plural the *one / other* split can't supply.

**Agreement:** a `{placeholder}` drops a value into a fixed frame, so the words around it must fit *every* value the app can supply. In inflected languages, write the frame in the case the surrounding preposition demands — German's duration fragments are **dative** because they land inside "…in {remaining}" (`in {count} Tagen`, `weniger als einer Minute`), not nominative `Tage`. Check the key that *consumes* the fragment (here `tray.session.expiresIn`) before choosing the form.

---

## Glossary

**Tier A — never translate (brands):** `NetBird` · `WireGuard®` · `Rosenpass` · `GitHub` · `ICE` · company/product names · sample URLs · version numbers.

When a brand sits beside a common noun, keep its exact spelling but join them the way your language builds such phrases — a hyphen, a connector word, an inflected noun — rather than copying English's bare noun-stack.

**Tier B — keep as-is (acronyms):** `SSO` · `MFA` · `DNS` · `IP`/`IPv6` · `ACL` · `SSH` · `GUI` · `P2P` · `URL` · `TCP`/`UDP`.

**Tier C — judgment.** One rule decides every term:

> **Use the word that language's IT users actually say.** Translate when a natural, common term exists; keep the English term *only* when the literal translation would be awkward or no one in that field really uses it.

Apply each term **consistently** — same English term → same translation everywhere — and keep a term once you've settled it. Whether a term stays English or takes a native word is **language-dependent**: a technical loanword (e.g. *Daemon*, *Handshake*) often stays, an everyday word (e.g. *Latency*, *Public key*) usually localizes, and some (*Exit Node*, *Peer*) go either way depending on the language. Decide per term with the rule above — a foreign origin alone is no reason to keep English. **Your main reference is the existing bundles:** match how a term was already rendered for your language rather than re-deciding it.

Two checks before you commit a term:

- **Prefer established localized wording.** If a widely used tool in this space (for example WireGuard) ships your language, its wording for a shared term such as *handshake* is what users already expect — look at the translated app, not just English docs. For generic UI verbs and formal address, follow your OS vendor's style guide (Microsoft / Apple / Google).
- **Watch for false friends.** A literal translation can collide with a *different* established term in your field — confirm your word doesn't already mean something else in this domain before using it.

---

## Style

| ✅ Do | ❌ Don't |
|---|---|
| Use the **formal "you"** (de *Sie*, fr *vous*, ru *вы*, it *Lei*, zh 您) | Use casual/informal address |
| Keep **buttons, menu, and tray** items short, in your language's action form (de "Speichern", fr "Enregistrer") | Let a label run much longer than the English — space is tight |
| Follow **locale punctuation** (fr NBSP + « », de „…", zh full-width), including around a quoted UI label | Carry over English Title Case (use sentence case; German nouns excepted) |
| Translate a term the **same way everywhere** | Vary wording for the same concept across screens |

Where it reads naturally, aim to keep each string **roughly the same length** as the English — the UI is tight and over-long strings can wrap or truncate. It's a soft preference, not a rule: if your language simply needs more words, use them.

A few habits that keep a bundle reading like one product rather than a word-for-word port:

- **Translate meaning, not words.** Render what a string *does*. An idiom or an awkward source phrase should become natural in your language, not a literal calque.
- **Keep one voice within a family.** Sibling strings — the connection states, every settings *help* caption, every "… Failed" title — should share a grammatical form. If one member sounds wrong in that form, re-voice the whole family rather than leave one odd sibling.
- **Mirror opposites.** A status should read as the natural counterpart of its pair: translate *Disconnected* as the opposite of however you rendered *Connected*, not as an unrelated word. Same for Active/Inactive, Selected/Not selected.
- **Give a standalone label its subject.** A bare button or title can lose the context the surrounding English UI implied — add the noun back if it would otherwise read ambiguously.

---

## Procedure

**New language** — read `en/common.json` *with* descriptions → settle your Tier C terms → write `i18n/locales/<code>/common.json` (same keys and order as `en`, `message` only, placeholders & brands preserved) → add a row to `_index.json` (`{"code","displayName"` = native name`,"englishName"}`) → run the QA list. Use the locale-code style the existing entries use (e.g. `fr`, `pt`, `zh-CN`).

**Review (de / hu / …)** — read source and target side by side; for each key check glossary conformance (e.g. de `Exit-Node` → `Exit Node`, hu `Kilépő csomópont` → `Exit Node`), placeholder/`\n` integrity, consistency, tone, and that the meaning matches the English `description`. Fix in place, then report what you changed (especially term standardizations) so a native speaker can sanity-check.

---

## QA before you finish

- [ ] Valid JSON · **every `en` key** present, same order · **no `description`** fields
- [ ] Every `{placeholder}`, `\n`, and intentional space preserved · `...` / `… Failed` / `{name}` quotes kept
- [ ] Tier A/B left intact · Tier C applied consistently (and matching the existing bundle for your language)
- [ ] Buttons & tray short · locale punctuation and capitalization applied
- [ ] New language added to `_index.json`
- [ ] **Tested in the running app** ↓

---

## Test it in the app

A bundle can pass every check above and still read wrong on screen. **Run the app, switch to your language, and click through the real surfaces** — tray menu, main window, every Settings tab, the dialogs. Watch for text overflow or truncation, labels that are technically right but wrong *for what the control does*, leaked placeholders, and terms that drift between screens.

How to run the app and switch language: see the project README. Can't run it (e.g. a headless agent)? Say so in your summary — don't silently skip this step.
