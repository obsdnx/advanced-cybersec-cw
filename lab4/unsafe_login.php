<?php
/*
 * Lab 4 — SQL Injection
 * Task: Vulnerable login page (string-concatenated query)
 * Description:
 *   Demonstrates a classic SQL injection vulnerability.
 *   User-supplied input is embedded directly into the SQL string without
 *   sanitisation or parameterisation, allowing an attacker to:
 *     - Log in as any user without knowing the password.
 *     - Dump all rows from the credential table.
 *     - Infer the database schema via error messages or blind injection.
 *
 * Injection examples (enter in the Username field):
 *   admin'--            : Logs in as admin; -- comments out the password check
 *   ' OR '1'='1         : Returns all rows (logs in as the first user)
 *   ' OR '1'='1' -- -   : Alternative comment syntax
 */

// =============================================================================
// Database connection
// =============================================================================

function getDB() {
    // Connection parameters for the lab MySQL container
    $dbhost = "10.9.0.6";     // MySQL server IP (docker network)
    $dbuser = "seed";          // DB username
    $dbpass = "dees";          // DB password
    $dbname = "sqllab_users";  // Database name

    $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    return $conn;
}

// =============================================================================
// Read user input — INJECTION POINTS
// =============================================================================

// Input arrives via GET parameters (also present in the URL, making it
// trivially testable by modifying the browser address bar).
$input_uname = $_GET['username'];   // <-- INJECTION POINT 1: not sanitised
$input_pwd   = $_GET['Password'];   // Raw password before hashing

// Hash the password with SHA-1 before comparing against the stored hash.
// NOTE: SHA-1 is cryptographically weak; use bcrypt/Argon2 in production.
$hashed_pwd = sha1($input_pwd);

// =============================================================================
// Vulnerable SQL query — string concatenation
// =============================================================================
// The username is embedded directly into the SQL string.
// If $input_uname = "admin'--", the query becomes:
//
//   SELECT id,name,eid,salary,ssn
//   FROM credential
//   WHERE name='admin'--' and Password='...'
//
// The -- starts a SQL comment, causing the password check to be ignored.
// The attacker is logged in as admin with any password (or no password).

$conn = getDB();

$sql = "SELECT id, name, eid, salary, ssn "     // Selected columns
     . "FROM credential "                         // Table
     . "WHERE name='" . $input_uname . "' "      // <-- $input_uname injected HERE
     . "and Password='" . $hashed_pwd . "'";      // Password check (can be bypassed)

$result = $conn->query($sql);

// =============================================================================
// Display results
// =============================================================================

if ($result && $result->num_rows > 0) {
    // Authentication succeeded — display the user's profile data
    echo "<p>Login successful!</p>";
    echo "<table border='1'>";
    echo "<tr><th>ID</th><th>Name</th><th>EID</th><th>Salary</th><th>SSN</th></tr>";

    while ($row = $result->fetch_assoc()) {
        echo "<tr>";
        echo "<td>" . htmlspecialchars($row['id'])     . "</td>";
        echo "<td>" . htmlspecialchars($row['name'])   . "</td>";
        echo "<td>" . htmlspecialchars($row['eid'])    . "</td>";
        echo "<td>" . htmlspecialchars($row['salary']) . "</td>";
        echo "<td>" . htmlspecialchars($row['ssn'])    . "</td>";
        echo "</tr>";
    }

    echo "</table>";
} else {
    // Authentication failed — wrong username or password
    echo "<p>Login failed: invalid username or password.</p>";
}

$conn->close();
?>
