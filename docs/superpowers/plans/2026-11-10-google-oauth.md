# Google OAuth implementation plan

Goal: Google-only sign-in and signup, retaining password-derived vault encryption.

Architecture: Google Identity Services popup returns a single-use authorization code.
The C++ backend checks the request origin and custom CSRF header, exchanges the code
with Google using its client secret, and reads the verified identity from Google's
userinfo endpoint over TLS. Google subject IDs bind accounts; linking requires the
existing vault password. No Google access/refresh tokens are persisted.

- [x] Test signup, subject binding, password checks, and vault-key preservation.
- [x] Add the Google code exchange and account binding, replacing email login.
- [x] Replace login/signup UI with Google plus master-password unlock/setup.
- [x] Document client ID/secret and origin configuration; build and run tests.

Scope: Auth, Database, main routes, Middleware origin check, login API/UI,
CMake/Docker dependencies, environment templates, Render config, tests, README.
Existing data is preserved. OAuth cannot be tested live without Google credentials.

Validation: frontend production build, C++ server compilation, CMake build and
CTest authentication suite passed. HTTP checks rejected disallowed origins,
missing CSRF headers, malformed payloads, removed email/OTP endpoints, and
unauthenticated vault access. Google code exchange follows the documented GIS
popup flow. Live Google consent remains untested without credentials.

The GitHub nlohmann release download failed with a TLS connection error in the
build container. The successful CMake check used the installed nlohmann 3.11.2
headers through FETCHCONTENT_SOURCE_DIR_JSON; SQLite used the configured download.
Production dependency versions and TLS verification settings were unchanged.
