<?php
// login.php
// Secure login system with role based session routing
// Now with lockout protection, email verification checks, and CSRF

require_once 'includes/header.php';
require_once 'includes/db.php';
require_once 'includes/csrf.php';
require_once 'includes/smtp_config.php'; // Needed for MAX_LOGIN_ATTEMPTS
require_once 'includes/mailer.php';


if (is_logged_in()) {
    if ($_SESSION['user_role'] === 'owner') {
        header("Location: owner/dashboard.php");
    } else {
        header("Location: player/dashboard.php");
    }
    exit;
}

$error_msg = "";
$email = $role = "";
$show_resend_link = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. CSRF Protection
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_msg = "Security token invalid or expired. Please try again.";
    } else {
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? 'player';

        if (empty($email) || empty($password) || empty($role)) {
            $error_msg = "Please enter both email and password.";
        } else {
            try {
                // Fetch user by email & role
                $stmt = $conn->prepare("SELECT * FROM users WHERE email = :email AND role = :role");
                $stmt->execute(['email' => $email, 'role' => $role]);
                $user = $stmt->fetch();

                if ($user) {
                    // 2. Lockout Check
                    if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
                        $minutes_left = ceil((strtotime($user['locked_until']) - time()) / 60);
                        $error_msg = "Account is locked due to too many failed attempts. Please try again in {$minutes_left} minute(s).";
                    }
                    // 3. Email Verification Check
                    elseif ($user['email_verified'] == 0) {
                        $error_msg = "Please verify your email before logging in.";
                        $show_resend_link = true;
                    }
                    // 4. Password Verification
                    elseif (password_verify($password, $user['password'])) {
                        // Success!
                        // Secure session regeneration to prevent fixation
                        session_regenerate_id(true);

                        // Check if an OTP was recently generated (within last 60 seconds)
                        $check_stmt = $conn->prepare("SELECT created_at FROM login_otps WHERE user_id = :user_id ORDER BY created_at DESC LIMIT 1");
                        $check_stmt->execute(['user_id' => $user['id']]);
                        $last_otp = $check_stmt->fetch();
                        $rate_limit_active = false;
                        if ($last_otp) {
                            $seconds_since = time() - strtotime($last_otp['created_at']);
                            if ($seconds_since < 60) {
                                $rate_limit_active = true;
                            }
                        }

                        if (!$rate_limit_active) {
                            // Generate secure 6-digit OTP code
                            $otp = strval(random_int(100000, 999999));
                            $otp_hash = password_hash($otp, PASSWORD_DEFAULT);

                            // Delete any previous OTPs for this user
                            $del_stmt = $conn->prepare("DELETE FROM login_otps WHERE user_id = :user_id");
                            $del_stmt->execute(['user_id' => $user['id']]);

                            // Store hashed OTP with 5 minute expiration
                            $expiry = date('Y-m-d H:i:s', time() + 5 * 60);
                            $ins_stmt = $conn->prepare("INSERT INTO login_otps (user_id, otp_hash, expires_at) VALUES (:user_id, :otp_hash, :expires_at)");
                            $ins_stmt->execute([
                                'user_id' => $user['id'],
                                'otp_hash' => $otp_hash,
                                'expires_at' => $expiry
                            ]);

                            // Send OTP to user's registered email
                            send_otp_email($user['email'], $user['name'], $otp);
                        }

                        // Store temporary user id in session
                        $_SESSION['otp_user_id'] = $user['id'];
                        header("Location: verify_otp.php");
                        exit;
                    } else {
                        // Failed password attempt
                        $attempts = $user['login_attempts'] + 1;
                        $locked_until = null;

                        if ($attempts >= MAX_LOGIN_ATTEMPTS) {
                            $locked_until = date('Y-m-d H:i:s', time() + LOCKOUT_DURATION);
                            $error_msg = "Too many failed attempts. Your account has been locked for 15 minutes.";
                        } else {
                            $error_msg = "Invalid email, password, or role selection.";
                        }

                        // Update attempts in DB
                        $fail_stmt = $conn->prepare("UPDATE users SET login_attempts = :attempts, locked_until = :locked WHERE id = :id");
                        $fail_stmt->execute([
                            'attempts' => $attempts,
                            'locked' => $locked_until,
                            'id' => $user['id']
                        ]);
                    }
                } else {
                    // User not found for that role (Harmonized message)
                    $error_msg = "Invalid email, password, or role selection.";
                }
            } catch (PDOException $e) {
                $error_msg = "Database error: " . $e->getMessage();
            }
        }
    }
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
                <a href="index.php" class="btn-back-website">Back to website &rarr;</a>
            </div>

            <div class="auth-split-promo-text">
                <h2>Play More, Worry Less</h2>
                <p>Book premium futsal fields instantly, earn reward points, and manage your bookings with ease.</p>
                <div class="carousel-indicators-mini">
                    <span class="dot active"></span>
                    <span class="dot"></span>
                    <span class="dot"></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Right Column: Login Form -->
    <div class="auth-split-form-container">
        <div class="auth-split-form-box">
            <!-- Mobile header (hidden on desktop) -->
            <div class="mobile-auth-header">
                <a href="index.php" class="logo">
                    HAMRO<span>FUTSAL</span>
                </a>
                <a href="index.php" class="btn-back-website-mobile">&larr; Home</a>
            </div>

            <h2>Welcome Back</h2>
            <p class="subtitle">Don't have an account yet? <a href="register.php">Register here</a></p>

            <!-- Display session flash notifications if set -->
            <?php display_flash_message(); ?>

            <?php if (!empty($error_msg)): ?>
                <div class="auth-error-box">
                    <?php echo sanitize($error_msg); ?>
                    <?php if ($show_resend_link): ?>
                        <div style="margin-top: 8px;">
                            <a href="resend_verification.php">Resend verification email</a>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <form action="login.php" method="POST" autocomplete="off">
                <!-- CSRF Token -->
                <?php csrf_input_field(); ?>

                <div class="form-group">
                    <label class="form-label">Login As</label>
                    <div class="segmented-control">
                        <div class="segmented-option">
                            <input type="radio" id="role-player" name="role" value="player" <?php echo ($role === 'player' || empty($role)) ? 'checked' : ''; ?>>
                            <label for="role-player">Player</label>
                        </div>
                        <div class="segmented-option">
                            <input type="radio" id="role-owner" name="role" value="owner" <?php echo ($role === 'owner') ? 'checked' : ''; ?>>
                            <label for="role-owner">Futsal Owner</label>
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label for="email" class="form-label">Email Address</label>

                    <!-- Hidden fake field to trick browser autofill -->
                    <input type="text" name="fake_username" style="display:none;">

                    <input type="email" id="email" name="email" class="form-control" placeholder="e.g. name@example.com"
                        value="<?php echo sanitize($email); ?>" autocomplete="new-password" required>
                </div>

                <div class="form-group">
                    <div
                        style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                        <label for="password" class="form-label" style="margin-bottom: 0;">Password</label>
                        <a href="forgot_password.php"
                            style="font-size: 0.85rem; color: var(--primary-color); font-weight: 500;">Forgot
                            Password?</a>
                    </div>

                    <!-- Hidden fake password field -->
                    <input type="password" name="fake_password" style="display:none;">

                    <input type="password" id="password" name="password" class="form-control"
                        placeholder="Enter your password" autocomplete="new-password" required>
                </div>



                <button type="submit" class="btn btn-primary btn-block" style="margin-top: 1.5rem;">SIGN IN</button>
            </form>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>