# BreachAlert

A data breach monitoring service. Users add an email address, confirm it through a verification link, and BreachAlert checks it against known data breaches and alerts them when new ones appear.

## Features
- Email sign-up with confirmation link
- Breach check endpoint with a breach timeline dashboard
- Actionable advice based on the type of data leaked
- 24-hour result caching (SQLite)
- Nightly automatic scan of all verified emails (APScheduler)
- Alert emails when new breaches are found

## Tech stack
Python, FastAPI, SQLite, APScheduler, HTML

## How to run
1. Install packages: `python -m pip install -r requirements.txt`
2. Start the server: `python -m uvicorn main:app --reload`
3. Open http://127.0.0.1:8000 for the dashboard, or /docs to test the API

## Status
Currently uses sample breach data. Connecting the real Have I Been Pwned API, real email sending, Stripe payments, and deployment are planned next.
