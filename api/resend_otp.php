<?php
// api/resend_otp.php
// Backend JSON API for rate-limiting and resending a new OTP code during login

header('Content-Type: application/json');

// Start session if needed
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once '../includes/db.php';
require_once '../includes/auth.php';
require_once '../includes/mailer.php';

// Allow only POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed.']);
    exit;
}

// Ensure the user has passed the initial email/password check
if (!isset($_SESSION['otp_user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Session expired or invalid. Please log in again.']);
    exit;
}

$user_id = $_SESSION['otp_user_id'];

// Get POST variables
$csrf_token = $_POST['csrf_token'] ?? '';

// Validate CSRF token
if (!verify_csrf_token($csrf_token)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Security token invalid or expired. Please refresh the page.']);
    exit;
}

try {
    // 1. Enforce 60-second cooldown rate limit
    $stmt = $conn->prepare("SELECT created_at FROM login_otps WHERE user_id = :user_id ORDER BY created_at DESC LIMIT 1");
    $stmt->execute(['user_id' => $user_id]);
    $last_otp = $stmt->fetch();
    
    if ($last_otp) {
        $seconds_since = time() - strtotime($last_otp['created_at']);
        if ($seconds_since < 60) {
            $seconds_left = 60 - $seconds_since;
            echo json_encode([
                'success' => false,
                'error' => "Please wait {$seconds_left} second(s) before requesting a new code.",
                'seconds_left' => $seconds_left
            ]);
            exit;
        }
    }
    
    // 2. Fetch user details to send the email
    $user_stmt = $conn->prepare("SELECT email, name FROM users WHERE id = :id");
    $user_stmt->execute(['id' => $user_id]);
    $user = $user_stmt->fetch();
    
    if (!$user) {
        echo json_encode(['success' => false, 'error' => 'User account not found.']);
        exit;
    }
    
    // 3. Generate secure 6-digit OTP
    $otp = strval(random_int(100000, 999999));
    $otp_hash = password_hash($otp, PASSWORD_DEFAULT);
    
    // 4. Delete old OTPs for user
    $del_stmt = $conn->prepare("DELETE FROM login_otps WHERE user_id = :user_id");
    $del_stmt->execute(['user_id' => $user_id]);
    
    // 5. Store new OTP in database
    $expiry = date('Y-m-d H:i:s', time() + 5 * 60); // 5 minutes expiry
    $ins_stmt = $conn->prepare("INSERT INTO login_otps (user_id, otp_hash, expires_at) VALUES (:user_id, :otp_hash, :expires_at)");
    $ins_stmt->execute([
        'user_id' => $user_id,
        'otp_hash' => $otp_hash,
        'expires_at' => $expiry
    ]);
    
    // 6. Send the code via email
    $sent = send_otp_email($user['email'], $user['name'], $otp);
    
    if ($sent) {
        echo json_encode([
            'success' => true,
            'message' => 'A new login verification code has been sent to your email.'
        ]);
        exit;
    } else {
        echo json_encode([
            'success' => false,
            'error' => 'Failed to send verification code. Please check your network connection or try again.'
        ]);
        exit;
    }
    
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
    exit;
}
