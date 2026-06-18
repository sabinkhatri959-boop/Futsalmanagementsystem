<?php
// verify_otp.php
// UI Page for entering the 6-digit Login OTP

require_once 'includes/header.php';
require_once 'includes/db.php';
require_once 'includes/csrf.php';

if (is_logged_in()) {
    if ($_SESSION['user_role'] === 'owner') {
        header("Location: owner/dashboard.php");
    } else {
        header("Location: player/dashboard.php");
    }
    exit;
}

if (!isset($_SESSION['otp_user_id'])) {
    set_flash_message("Please log in first.", "danger");
    header("Location: login.php");
    exit;
}

try {
    $stmt = $conn->prepare("SELECT email, name FROM users WHERE id = :id");
    $stmt->execute(['id' => $_SESSION['otp_user_id']]);
    $user = $stmt->fetch();
    
    if (!$user) {
        unset($_SESSION['otp_user_id']);
        set_flash_message("User not found.", "danger");
        header("Location: login.php");
        exit;
    }
    
    // Mask email for privacy (e.g. s***@gmail.com)
    $email = $user['email'];
    $parts = explode("@", $email);
    if (count($parts) === 2) {
        $name_part = $parts[0];
        $domain_part = $parts[1];
        $len = strlen($name_part);
        if ($len > 2) {
            $masked_name = substr($name_part, 0, 1) . str_repeat("*", $len - 2) . substr($name_part, -1);
        } else {
            $masked_name = $name_part . str_repeat("*", 3);
        }
        $masked_email = $masked_name . '@' . $domain_part;
    } else {
        $masked_email = $email;
    }
} catch (PDOException $e) {
    set_flash_message("Database error: " . $e->getMessage(), "danger");
    header("Location: login.php");
    exit;
}
?>

<div class="auth-split-wrapper">
    <!-- Left Column: Branding and Image -->
    <div class="auth-split-image" style="background-image: url('assets/images/default_futsal.jpg');">
        <div class="auth-split-image-overlay"></div>
        <div class="auth-split-image-content">
            <div class="auth-split-logo-row">
                <a href="index.php" class="logo">
                    HAMRO<span>FUTSAL</span>
                </a>
                <a href="login.php" class="btn-back-website">&larr; Back to Login</a>
            </div>

            <div class="auth-split-promo-text">
                <h2>Secure Your Sign In</h2>
                <p>We've sent a 6-digit verification code (OTP) to your email to verify your identity before accessing your dashboard.</p>
                <div class="carousel-indicators-mini">
                    <span class="dot"></span>
                    <span class="dot active"></span>
                    <span class="dot"></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Right Column: OTP Verification Form -->
    <div class="auth-split-form-container">
        <div class="auth-split-form-box">
            <!-- Mobile header (hidden on desktop) -->
            <div class="mobile-auth-header">
                <a href="index.php" class="logo">
                    HAMRO<span>FUTSAL</span>
                </a>
                <a href="login.php" class="btn-back-website-mobile">&larr; Login</a>
            </div>

            <h2>Enter Verification Code</h2>
            <p class="subtitle">A 6-digit code has been sent to <strong><?php echo sanitize($masked_email); ?></strong></p>

            <!-- Status Alert Box -->
            <div id="otp-alert" class="auth-error-box" style="display: none;"></div>

            <form id="otpForm" autocomplete="off">
                <!-- CSRF Token -->
                <?php csrf_input_field(); ?>

                <div class="form-group" style="text-align: center;">
                    <label for="otp" class="form-label" style="text-align: left;">One-Time Password (OTP)</label>
                    <input type="text" id="otp" name="otp" class="form-control" placeholder="000000" maxlength="6" 
                           pattern="\d{6}" style="text-align: center; font-size: 2rem; letter-spacing: 10px; font-weight: 600; padding: 10px;" required autofocus>
                    <span class="validation-hint" id="otp-hint">Enter the 6 digits sent to your inbox.</span>
                </div>

                <button type="submit" id="verifyBtn" class="btn btn-primary btn-block" style="margin-top: 1.5rem;">VERIFY CODE</button>
            </form>

            <div style="margin-top: 2rem; text-align: center;">
                <p class="text-muted" style="font-size: 0.9rem; margin-bottom: 0.5rem;">Didn't receive the code?</p>
                <button id="resendBtn" class="btn btn-outline" style="min-width: 160px; padding: 8px 16px; font-size: 0.9rem;" disabled>
                    Resend Code <span id="cooldown-timer">(60s)</span>
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Load OTP interaction script -->
<script src="js/otp.js"></script>

<?php require_once 'includes/footer.php'; ?>
