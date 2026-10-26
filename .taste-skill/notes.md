# HostingInside WAF console — redesign notes

User ask: stop copying SafeLine; make an original console. Keep every feature.

## What was SafeLine's and goes
- Menu names and IA: Statistics / Applications / Attacks / Allow & Deny / HTTP Flood (Rate Limiting,
  Waiting Room) / Anti-Bot / Auth / Settings.
- Application cards with mode chip, "RQS TD / BLK TD", HTTP FLOOD / BOT PROTECT / AUTH / ATTACKS chips.
- Add Application dialog field order (domain chips, port rows with HTTP/HTTPS toggles, SSL cert,
  Reverse Proxy / Static / Redirect radios, upstream, name, description).
- Teal brand, globe/world-map hero, "Traffic analysis" tab, the "Semantic analysis" banner,
  Defense/Audit/Disabled wording, Events/Logs toggle on every page.

## Inventory (data and jobs)
- Objects: sites (domains, ports, origin, mode, detection level), threats (one Coraza transaction:
  rules, category, payload, source IP, country, stopped or watched), access rules (allow/deny,
  conditions, scope), IP lists, bans (IP, site, until, reason), traffic (requests per bucket,
  4xx/5xx), certificates (expiry), gate/queue/challenge events, API tokens.
- Magnitudes (dev lab): 1-20 sites; hundreds to a few thousand requests per site per day; tens of
  threats a day, bursts from one source; 0-10 active bans; certificates 0-90 days left.
- People: HostingInside ops/security engineers. Glance a few times a day; investigation sessions
  when a site is hit. Desktop mostly; phone for "is it on fire?".
- Jobs, most frequent first: (1) see what is hitting us and stop the source; (2) tune a false
  positive (switch a site to Watch, allow a path); (3) add a site; (4) lift a ban; (5) renew a cert.
- Product's own things: HostingInside = 鷹式特網, "eagle-style network" -> the eagle watches from above;
  the request's path through the engine (rules -> rate limit -> gate -> queue -> challenge -> WAF ->
  origin); CRS rule IDs; Taiwan.

## Vocabulary (ours)
Overview · Sites · Threats · Access · Activity · Settings.
Site modes: Block (stop threats) · Watch (log, let through) · Off.
Pipeline stages: Access rules · Rate limits · Password gate · Queue · Bot check · Threat inspection.
"Origin" for upstream. "Source" for the attacking IP.

## Style: data-terminal (dark), seed 165432458
Why: a WAF console is watched in long sessions like a monitoring screen; dark data-terminal is also
the furthest from SafeLine's light teal cards.

## Face (chosen): the system's own signature as the lead
The request pipeline, drawn as one horizontal "checkpoint line": requests enter on the left and each
stage shows how many it stopped, ending with what reached the origin. Only this engine has this
order of stages. Plus an eagle mark (wing chevron) in the accent at the top of the rail.
Accent stays the dealt blue #4a8ad6 (no HostingInside hue found).

## Screen questions
- Overview: "Is anything getting through or hammering a site right now?" Biggest block: the
  checkpoint line for the window. Finding: the top threat source in words. Job: stop that source.
- Sites: "Which site needs attention?" Job: add a site.
- Site: "Is this site guarded the way it should be, and what is hitting it?" The pipeline is the
  settings editor: one row per stage, in engine order.
- Threats: "Who is attacking, and was it stopped?" Inbox: sources on the left, the selected
  source's requests and matched rules on the right. Job: deny the source / allow a false positive.
- Access: "Who is allowed and who is refused?" Rules in evaluation order, IP lists, active bans.
- Activity: "What did the non-WAF stages do?" One log of denies, bans, challenges, gate logins.
- Settings: certificates (expiry first), account & 2FA, API tokens, system.

## Critique (round 3, from the server inspector's screenshots)
Inspector: 0 FAIL on every screen at 1440/768/390. WARNs kept, with reasons:
- hero-void on Sites, Access, Settings: list screens holding 1-5 real rows; padding them would invent data.
- ragged-row on Threats: a two-pane inbox; the detail's length follows the selected source.
- lint: zero-padding is for clock times; the em dash is the grey "missing value" mark.
1. Question answered by the biggest thing? Overview: yes, the checkpoint line, with the finding naming the
   largest stopped source (fixed: it used to name the newest source, a Watch-mode office IP).
2. Edges: one left edge from title to rows; Overview row 3 balanced with a totals row.
3. Colour: accent only on selection lines, the "stopped" series, stage bars and the eagle mark.
4. Numbers: stopped-by-inspection equals blocked threats (asserted in demo/data.ts); per-site totals sum.
   Fixed: demo events named the wrong rule for /wp-admin paths; wiki threats had future timestamps.
5. Zeros print as 0 ("nobody had to wait"); missing values as a grey dash.
6. One legend, drawn by charts.js from the same series.
7. Phone: rail folds into a bottom bar with labels; panels and tables stack; rows no longer overflow.
