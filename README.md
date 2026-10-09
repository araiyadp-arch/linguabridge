# LinguaBridge

A non-profit, private English-learning platform for students ages 5–17, built one approved component at a time.

## What's in this repo

Static HTML pages — each one is self-contained (inline CSS/JS, embedded audio) and can be opened directly or served as-is by any static host.

- `index.html` — homepage (same as `linguabridge-homepage.html`, duplicated as the domain root)
- `linguabridge-homepage.html` — homepage
- `linguabridge-about.html` — about page
- `linguabridge-login-2.html` — login
- `linguabridge-quiz-2.html` — 15-question placement quiz (Explorer → Builder → Communicator → Leader placement)
- `linguabridge-dashboard.html` — student dashboard (daily lesson unlock, chapter/level progress)
- `linguabridge-lesson.html` — lesson flow (vocab, conversation, listening, reading, pronunciation practice)
- `linguabridge-lesson-quiz.html` — 5-question lesson quiz
- `linguabridge-lesson-video.html` — lesson recap video
- `linguabridge-badge.html` — lesson-completion badge screen
- `linguabridge-see-you-tomorrow.html` — daily-lock / "come back tomorrow" screen

## Curriculum status

Explorer and Builder Chapters 1–2 (11 of ~50 Builder Adventures) have real, written lesson content. The remaining chapters across Builder, Communicator, and Leader have approved chapter titles and Adventure counts in the data model, but not yet authored lesson content — the dashboard shows an honest "more Adventures coming soon" state rather than placeholder content for those.

## Deployment

A `CNAME` file is included for `lingua-bridge.us`. This repo is laid out for GitHub Pages (enable Pages in repo Settings → Pages → Deploy from a branch) or any static host that can serve a flat folder of HTML files.
