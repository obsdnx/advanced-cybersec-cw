<?php
/*
 * Lab 4 — SQL Injection
 * Task: Fixed login page using prepared statements
 * Description:
 *   Replaces the vulnerable string-concatenated query with a parameterised
 *   prepared statement.  The database driver separates SQL code from user
 *   data, making injection impossible regardless of the input content.
 *
 * Key defence — prepared statements:
 *   1. prepare()     — sends the SQL template to the DB; special chars are safe.
 *   2. bind_param()  — binds user values as typed parameters, never as SQL code.
 *   3. execute()     — runs the query with the bound parameters.
 *   No amount of SQL metacharacters (', --, ;, etc.) in the input can alter
 *   the query structure because the input is treated as a string literal value.
 */

// =============================================================================
// Database connection (same as unsafe_login.php)
// =============================================================================

function getDB() {
    $dbhost = "10.9.0.6";
    $dbuser = "seed";
    $dbpass = "dees";
    $dbname = "sqllab_users";

    $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    return $conn;
}

// =============================================================================
// Read and hash user input
// =============================================================================

$input_uname = $_GET['username'];   // Still taken from GET — but now safe
$input_pwd   = $_GET['Password'];
$hashed_pwd  = sha1($input_pwd);

// =============================================================================
// Safe query using prepared statements
// =============================================================================

$conn = getDB();

// Step 1: prepare() — send the SQL template with ? placeholders.
// The database parses and compiles the query structure at this point.
// No user data is present yet, so injection is structurally impossible.

$stmt = $conn->prepare(
    "SELECT id, name, eid, salary, ssn "
  . "FROM credential "
  . "WHERE name = ? AND Password = ?"
);
// The two ? marks are the placeholders for username and hashed password.

if (!$stmt) {
    die("Prepare failed: " . $conn->error);
}

// Step 2: bind_param() — attach user values to the placeholders.
// "ss" means both parameters are strings (other type codes: i=int, d=double, b=blob).
// The driver ensures these values are treated as data, not as SQL syntax.

$stmt->bind_param("ss", $input_uname, $hashed_pwd);

// Step 3: execute() — run the compiled query with the bound values.

$stmt->execute();

// Step 4: bind_result() — map result columns to PHP variables.
// This avoids fetch_assoc() and processes the result set safely.

$stmt->bind_result($id, $name, $eid, $salary, $ssn);

// =============================================================================
// Display results
// =============================================================================

$found = false;

if ($stmt->fetch()) {
    // fetch() returns true if a row was returned (authentication succeeded)
    $found = true;

    echo "<p>Login successful!</p>";
    echo "<table border='1'>";
    echo "<tr><th>ID</th><th>Name</th><th>EID</th><th>Salary</th><th>SSN</th></tr>";

    do {
        echo "<tr>";
        echo "<td>" . htmlspecialchars($id)     . "</td>";
        echo "<td>" . htmlspecialchars($name)   . "</td>";
        echo "<td>" . htmlspecialchars($eid)    . "</td>";
        echo "<td>" . htmlspecialchars($salary) . "</td>";
        echo "<td>" . htmlspecialchars($ssn)    . "</td>";
        echo "</tr>";
    } while ($stmt->fetch());   // Fetch subsequent rows (normally just one)

    echo "</table>";
}

if (!$found) {
    echo "<p>Login failed: invalid username or password.</p>";
}

$stmt->close();
$conn->close();
?>
