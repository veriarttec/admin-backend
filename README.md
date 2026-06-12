# Admin Portal Backend

FastAPI backend for the ArtPriv Admin Portal.

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your database URL and secret key

# Create admin users
python seed_admins.py

# Start server
uvicorn main:app --reload --port 8001
```

## Admin Accounts

Seed admin users with `python seed_admins.py`. The seed password is read from the
`ADMIN_SEED_PASSWORD` environment variable — set it before running the script and
rotate the password after first login. Never commit credentials to this repository.

## API Documentation

Once running, visit:
- Swagger UI: http://localhost:8001/docs
- ReDoc: http://localhost:8001/redoc

## Required Database Tables

This backend expects the following tables to exist in the database:

- `banks` - Bank entities with subscription info
- `donors` - Donor entities with state
- `donor_state_history` - Donor state changes
- `admins` - Admin users (created by seed script)
- `activity_logs` - Admin activity audit trail

## Environment Variables

See `.env.example` for all available configuration options.
