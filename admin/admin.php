<?php
// Database connection
try {
    // Connect to MySQL
    $pdo = new PDO('mysql:host=localhost;dbname=daw;charset=utf8', 'root', 'admine');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    // If there's an error, display a message and stop
    die('Erreur : ' . $e->getMessage());
}

// User  Functions
function createUser($name, $password, $type) {
    global $pdo;
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $pdo->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
    return $stmt->execute([$name, $hashedPassword, $type]);
}

function updateUserStatus($id, $status) {
    global $pdo;
    $stmt = $pdo->prepare("UPDATE users SET status = ? WHERE id = ?");
    return $stmt->execute([$status, $id]);
}

function getUserDetails($id) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Project  Functions
function createProject($title, $description, $teacher_id) {
    global $pdo;
    $stmt = $pdo->prepare("INSERT INTO projects (title, description, teacher_id) VALUES (?, ?, ?)");
    return $stmt->execute([$title, $description, $teacher_id]);
}

function updateProjectStatus($id, $status) {
    global $pdo;
    $stmt = $pdo->prepare("UPDATE projects SET status = ? WHERE id = ?");
    return $stmt->execute([$status, $id]);
}

function getProjects($status = null) {
    global $pdo;
    $query = "SELECT * FROM projects";
    if ($status) $query .= " WHERE status = ?";
    $stmt = $pdo->prepare($query);
    $stmt->execute($status ? [$status] : []);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Group  Functions
function createGroup($group_type, $project_id = null) {
    global $pdo;
    $stmt = $pdo->prepare("INSERT INTO groups (group_type, project_id) VALUES (?, ?)");
    return $stmt->execute([$group_type, $project_id]);
}

function addGroupMember($group_id, $student_id) {
    global $pdo;
    $stmt = $pdo->prepare("INSERT INTO groupstu (group_id, student_id) VALUES (?, ?)");
    return $stmt->execute([$group_id, $student_id]);
}

// API for User Management
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Input validation
    if (isset($data['username'], $data['password'], $data['role'])) {
        $username = $data['username'];
        $password = $data['password'];
        $role = $data['role'];

        if (createUser($username, $password, $role)) {
            echo json_encode(['success' => true, 'message' => 'User created successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to create user']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid input']);
    }
}
?>
