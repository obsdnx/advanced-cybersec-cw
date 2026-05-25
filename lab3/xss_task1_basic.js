/*
 * Lab 3 — XSS and CSP
 * Task 1: Basic Stored XSS — alert() proof of concept
 * Description:
 *   Demonstrates the simplest possible stored XSS payload.
 *   When injected into a profile field (e.g. the "Brief Description" field
 *   in Elgg), the script tag is stored in the database and executed in every
 *   victim's browser that views the attacker's profile.
 *
 * HOW IT WORKS:
 *   1. Attacker logs in and edits their profile.
 *   2. In a text field that is rendered without output encoding, they type
 *      the payload below.
 *   3. Elgg stores the raw HTML in its database.
 *   4. When any user visits the attacker's profile, Elgg fetches the stored
 *      value and injects it verbatim into the HTML page body.
 *   5. The browser parses the <script> tag and executes the JavaScript,
 *      displaying an alert dialog in the victim's browser context.
 *
 * WHY THIS WORKS (root cause):
 *   The application does not sanitise or HTML-encode user-supplied input
 *   before storing it, and does not encode it again before rendering it.
 *   Proper defences include:
 *     - htmlspecialchars() (PHP) / escapeHTML() before rendering output
 *     - A Content Security Policy that blocks inline scripts
 *     - Input validation / allowlist filtering on the server side
 */

// ============================================================
// PAYLOAD (paste this into the Elgg profile "About Me" field):
// ============================================================

// <script>alert('XSS')</script>

/*
 * Step-by-step execution trace:
 *
 *  Browser (attacker)                    Elgg server                DB
 *  ─────────────────────────────────────────────────────────────────────
 *  POST /action/profile/edit             ← receives POST data
 *    description=<script>alert(...)</script>
 *                                        stores raw HTML in DB ──► "description": "<script>...</script>"
 *
 *  Browser (victim visits attacker profile)
 *  GET /profile/attacker                 ← fetches profile
 *                                        queries DB ◄──────────── "<script>alert('XSS')</script>"
 *                                        renders HTML:
 *                                          <div class="elgg-output">
 *                                            <script>alert('XSS')</script>
 *                                          </div>
 *  ← receives HTML with embedded script
 *  JavaScript engine executes: alert('XSS')
 *  Victim sees: [popup] XSS
 *
 * The attacker's script runs in the victim's browser session, giving the
 * attacker access to the victim's cookies, session tokens, and the ability
 * to perform actions on their behalf (CSRF via XSS).
 */
