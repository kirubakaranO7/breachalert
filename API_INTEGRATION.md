# API Integration Guide

## Data source
BreachAlert is designed around the Have I Been Pwned (HIBP) API. A paid HIBP key was not available for this project, so the app currently runs on built-in sample breach data. The scanner is written so the real API is used automatically once a key is provided.

## Authentication
The key is read from the environment variable HIBP_API_KEY and is never written in the source code or committed to GitHub. If the variable is not set, the app falls back to sample data.

## Rate limiting strategy
- 24-hour cache: a lookup for the same email is reused for 24 hours instead of calling the API again (SQLite is used instead of Redis).
- Delay between calls: the nightly scan waits HIBP_DELAY_SECONDS between emails to stay under the API limit.
- Failed lookups are skipped and logged, so one error does not stop the whole scan.

## Background scanning
A nightly job (APScheduler) re-checks every verified email at 02:00, compares results with previously seen breaches, and sends an alert only for NEW breaches.

## Data retention policy
- Stored: email address, verification status, confirmation token, names of breaches already reported.
- Not stored: passwords or leaked data contents.
- Cached lookup results are treated as expired after 24 hours.

## Known limitations
- SQLite is used instead of Redis, and plain HTML instead of React.
- Alert emails are printed to the terminal until SMTP settings are configured.
