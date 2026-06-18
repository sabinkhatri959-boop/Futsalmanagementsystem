<?php
// api/verify_otp.php
// Backend JSON API for validating the OTP code during login

header('Content-Type: application/json');

// Start session if needed
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once '../includes/db.php';
require_once '../includes/auth.php';

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
$otp = trim($_POST['otp'] ?? '');
$csrf_token = $_POST['csrf_token'] ?? '';

// Validate CSRF token
if (!verify_csrf_token($csrf_token)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Security token invalid or expired. Please refresh the page.']);
    exit;
}

// Validate OTP format (must be 6 digits)
if (!preg_match('/^\d{6}$/', $otp)) {
    echo json_encode(['success' => false, 'error' => 'Verification code must be exactly 6 digits.']);
    exit;
}

try {
    // Retrieve the active OTP for this user
    $stmt = $conn->prepare("SELECT * FROM login_otps WHERE user_id = :user_id LIMIT 1");
    $stmt->execute(['user_id' => $user_id]);
    $otp_record = $stmt->fetch();
    
    if (!$otp_record) {
        echo json_encode(['success' => false, 'error' => 'No active verification code found. Please log in again.']);
        exit;
    }
    
    // Check if OTP has expired (5 minutes expiration)
    if (strtotime($otp_record['expires_at']) <= time()) {
        // Delete expired OTP
        $del_stmt = $conn->prepare("DELETE FROM login_otps WHERE id = :id");
        $del_stmt->execute(['id' => $otp_record['id']]);
        
        echo json_encode(['success' => false, 'error' => 'The verification code has expired. Please request a new one.']);
        exit;
    }
    
    // Check if the maximum attempts have been exceeded
    if ($otp_record['attempts'] >= 5) {
        // Delete OTP
        $del_stmt = $conn->prepare("DELETE FROM login_otps WHERE id = :id");
        $del_stmt->execute(['id' => $otp_record['id']]);
        
        echo json_encode(['success' => false, 'error' => 'Too many failed verification attempts. Please log in again.']);
        exit;
    }
    
    // Verify code
    if (password_verify($otp, $otp_record['otp_hash'])) {
        // SUCCESS!
        // Fetch user data to populate session
        $user_stmt = $conn->prepare("SELECT * FROM users WHERE id = :id");
        $user_stmt->execute(['id' => $user_id]);
        $user = $user_stmt->fetch();
        
        if (!$user) {
            echo json_encode(['success' => false, 'error' => 'User account not found.']);
            exit;
        }
        
        // Secure session regeneration
        session_regenerate_id(true);
        
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_name'] = $user['name'];
        $_SESSION['user_email'] = $user['email'];
        $_SESSION['user_role'] = $user['role'];
        $_SESSION['user_phone'] = $user['phone'];
        
        // Clean up temporary variables
        unset($_SESSION['otp_user_id']);
        
        // Delete verified OTP record from database
        $del_stmt = $conn->prepare("DELETE FROM login_otps WHERE id = :id");
        $del_stmt->execute(['id' => $otp_record['id']]);
        
        // Reset user login attempts and update last_login
        $update_stmt = $conn->prepare("UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = :id");
        $update_stmt->execute(['id' => $user_id]);
        
        set_flash_message("Welcome back, " . $user['name'] . "!", "success");
        
        // Determine redirect URL
        $redirect = ($user['role'] === 'owner') ? 'owner/dashboard.php' : 'player/dashboard.php';
        
        echo json_encode([
            'success' => true,
            'redirect' => $redirect
        ]);
        exit;
        
    } else {
        // Mismatch! Increment attempts
        $new_attempts = $otp_record['attempts'] + 1;
        $remaining = 5 - $new_attempts;
        
        if ($remaining <= 0) {
            // Delete OTP as limit reached
            $del_stmt = $conn->prepare("DELETE FROM login_otps WHERE id = :id");
            $del_stmt->execute(['id' => $otp_record['id']]);
            
            echo json_encode([
                'success' => false,
                'error' => 'Too many incorrect attempts. Your verification code is now invalid. Please log in again.'
            ]);
            exit;
        } else {
            // Update attempts count in database
            $up_stmt = $conn->prepare("UPDATE login_otps SET attempts = :attempts WHERE id = :id");
            $up_stmt->execute(['attempts' => $new_attempts, 'id' => $otp_record['id']]);
            
            echo json_encode([
                'success' => false,
                'error' => "Incorrect verification code. You have {$remaining} attempt(s) remaining.",
                'remaining' => $remaining
            ]);
            exit;
        }
    }
    
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
    exit;
}
