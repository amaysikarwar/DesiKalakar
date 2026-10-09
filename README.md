# Desi Kalakaar + existing Java backend

## Run locally
Requires Java 17+.

```bash
cd desi-kalakaar-integrated
java Server.java
```
Open http://localhost:8080.

## What is connected
- Login and new worker account creation use `POST /api/login` and `POST /api/register` with the backend's phone + 4-digit PIN model.
- Worker search uses `GET /api/workers`.
- Worker profile, verified jobs and integrity audit use `GET /api/workers/{id}` and `/audit`.
- “Log a completed job” uses `POST /api/jobs`; a worker must be logged in.
- The job list shows the logged-in worker's records from `GET /api/me`.

## Important limitations in the supplied backend
This backend is **SkillProof**, not a general job-board backend. It does not have endpoints to save worker skills/descriptions or to create/search public job vacancies. Those frontend fields are not persisted. The jobs API records completed work for client confirmation, not vacancies for workers to apply to.
`sendSms()` currently writes a simulated SMS to the server console / development outbox; it does not send real SMS. Do not present this as real OTP/SMS in production.
The backend defaults `DEV=true`, exposes a development outbox and uses a local JSON file for data. Before public launch, set `DEV=false`, configure a real SMS provider in `sendSms()`, and use durable database storage/backups. Also restrict CORS and add production security controls. This prototype uses the backend's existing 4-digit PIN login, not OTP login.
