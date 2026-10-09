# LinguaBridge

A non-profit, private English-learning platform for students ages 5–17, built one approved component at a time.

## What's in this repo

Static HTML pages, mostly self-contained (inline CSS/JS) and servable as-is by any static host (currently GitHub Pages).

- `index.html` — homepage (same as `linguabridge-homepage.html`, duplicated as the domain root)
- `linguabridge-homepage.html` — homepage
- `linguabridge-about.html` — about page
- `linguabridge-login-2.html` — founder login (calls the real backend, see "Backend" below)
- `linguabridge-quiz-2.html` — 15-question placement quiz (Explorer → Builder → Communicator → Leader placement)
- `linguabridge-dashboard.html` — student dashboard (daily lesson unlock, chapter/level progress; also has a founder-only Bridge-voice compare panel)
- `linguabridge-lesson.html` — lesson flow (vocab, conversation, listening, reading, pronunciation practice)
- `linguabridge-lesson-quiz.html` — 5-question lesson quiz
- `linguabridge-lesson-video.html` — lesson recap video
- `linguabridge-badge.html` — lesson-completion badge screen
- `linguabridge-see-you-tomorrow.html` — daily-lock / "come back tomorrow" screen
- `lb-core.js` — shared engine for the 6 lesson-flow pages above: progress state (`LB`), curriculum structure (`LEVELS`), and Bridge's TTS voice system (`AUDIO`/`bridgeSpeak`, all 4 recorded voices). Loaded once instead of duplicated per page (see "Architecture" below).
- `lb-content.js` — shared lesson/quiz content (`LESSON_CONTENT`) and lookup helpers (`advFor`/`chapterFor`) for those same 6 pages.
- `worker/` — the Cloudflare Worker backend (real founder authentication). See `worker/README.md`.

## Architecture

The 6 lesson-flow pages used to each embed a byte-for-byte identical ~6.1MB copy of `lb-core.js`/`lb-content.js`'s contents inline. That's been extracted into the two shared files above — pages now load them via `<script src>`, cutting each page from ~6.4MB to ~200KB with no change in behavior. Adding a new Builder/Communicator/Leader lesson means adding an entry to `LESSON_CONTENT` in `lb-content.js` (data), not writing a new HTML page or re-duplicating the engine.

## Curriculum status

Correcting an earlier version of this note: **Explorer** (the level students start on) currently has only 1 real written lesson (Chapter 1, flagged in-page as a sample/placeholder) — most of Explorer is not yet authored. **Builder** is actually the furthest along, with 11 real lessons covering its first two chapters ("My Daily Routine" + "School Life"). Communicator and Leader each have 1 sample lesson. All four levels' chapter titles and Adventure counts are approved and in `LEVELS` (in `lb-core.js`); content beyond what's listed above has not been authored yet — the dashboard shows an honest "more Adventures coming soon" state rather than placeholder content for those.

## Backend

Founder login is real (not a placeholder): a Cloudflare Worker (`worker/`) + D1 database at `api.lingua-bridge.us`, checked by `linguabridge-login-2.html` and `linguabridge-dashboard.html`. Real student accounts are a separate, not-yet-decided piece of work — see the project's roadmap doc, §14.

## Deployment

A `CNAME` file is included for `lingua-bridge.us`. This repo is laid out for GitHub Pages (enable Pages in repo Settings → Pages → Deploy from a branch) or any static host that can serve a flat folder of files.
