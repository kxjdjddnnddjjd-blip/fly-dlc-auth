# Fly DLC account gateway

Also relays opt-in GlobalView presence and vector menu miniatures through authenticated
`POST /globalview`. Firebase ID tokens are verified; only peers on the same hashed server
and current Tab list can see each other. Only the watched peer's menu is returned.
State expires after eight seconds and never enters Firestore or persistent storage.
Run `npm test` for login and two-session GlobalView integration tests. No new secrets or
paid services are required.

Nickname or email/password authentication for the Fly DLC website and Minecraft Chat.
Existing Firebase accounts and saved profiles are retained. Password verification
uses Firebase Authentication; there is no public nickname-to-email lookup.

Node 22+. Run `npm install`, `npm test`, `npm start`.

Render: free web service, build `npm ci`, start `npm start`, health `/health`.
Set FIREBASE_API_KEY (public Firebase application configuration) and
FIREBASE_SERVICE_ACCOUNT (private JSON, Render secret environment variable only).
The dedicated service account needs Firebase Authentication Viewer and Datastore Viewer.
Do not upload its key to GitHub or ship it in the client/site. No credentials are logged.

POST /login: `{ "identifier": "Admin", "password": "...", "client": "web" }`.
The web response is a Firebase custom token. Native clients receive Firebase ID/refresh
tokens after the same password check. CORS permits only the two Fly DLC production origins.
Requests are limited by IP and hashed account identifier; only POST JSON is accepted.
Email verification is not required. Firestore authorization still checks ownership,
profile identity, message authors, conversation members and message throttling.

Free Render services sleep after inactivity: the first nickname login can take about
a minute. Email login uses Firebase directly and does not depend on server wakeup.
Account data lives in Firebase, not on Render's temporary filesystem.
