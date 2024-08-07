-- +goose Up
-- +goose StatementBegin
INSERT INTO settings (name) VALUES ('SMTP_HOST');
INSERT INTO settings (name) VALUES ('SMTP_PORT');
INSERT INTO settings (name) VALUES ('SMTP_USER');
INSERT INTO settings (name) VALUES ('SMTP_PASSWORD');
INSERT INTO settings (name) VALUES ('SMTP_SENDER');

INSERT INTO settings (name, value) VALUES ('EMAIL_VERIFICATION_SUBJECT', 'Confirm your email address');
INSERT INTO settings (name) VALUES ('EMAIL_VERIFICATION_REDIRECT_URL');
INSERT INTO settings (name, value) VALUES ('EMAIL_VERIFICATION_BODY', '
  <!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confirm Your Email</title>
</head>

<body>
    <div>
        <h2>Dear new user</h2>
        <p>Thank you for registering with us!</p>
        <p>To complete your registration, please confirm your email address by clicking the link below:</p>
        <p>
            <a href="{{ .RedirectURL }}">Confirm Your Email Address</a>
        </p>
        <p>If the above link doesn’t work, you can copy and paste the following URL into your web browser:</p>
        <p>{{ .RedirectURL }}
        </p>
        <p>If you did not create an account using this email address, please ignore this email.</p>
        <p>Thank you<br>
    </div>
</body>

</html>
  ');

INSERT INTO settings (name, value) VALUES ('PASSWORD_RESET_SUBJECT', 'Reset your password');
INSERT INTO settings (name) VALUES ('PASSWORD_RESET_REDIRECT_URL');
INSERT INTO settings (name, value) VALUES ('PASSWORD_RESET_BODY', '
  <!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
</head>

<body>
    <div>
        <h2>Dear user,</h2>
        <p>to reset your password click on the link below </p>
        <p>
            <a href="{{ .RedirectURL }}">Confirm Your Email Address</a>
        </p>
        <p>If the above link doesn’t work, you can copy and paste the following URL into your web browser:</p>
        <p>{{ .RedirectURL }}
        </p>
        <p>If you did not create an account using this email address, please ignore this email.</p>
        <p>Thank you<br>
    </div>
</body>

</html>
  ');


INSERT INTO settings (name, value) VALUES ('MFA_VERIFICATION_SUBJECT', 'Confirm your email address');
INSERT INTO settings (name) VALUES ('MFA_VERIFICATION_REDIRECT_URL');
INSERT INTO settings (name, value) VALUES ('MFA_VERIFICATION_BODY', '
  <!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
</head>

<body>
    <div>
        <h2>Dear user,</h2>
        <p> to successfully login click on the link below </p>
        <p>
            <a href="{{ .RedirectURL }}">Confirm Your Email Address</a>
        </p>
        <p>If the above link doesn’t work, you can copy and paste the following URL into your web browser:</p>
        <p>{{ .RedirectURL }}
        </p>
        <p>If you did not create an account using this email address, please ignore this email.</p>
        <p>Thank you<br>
    </div>
</body>

</html>
  ');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings WHERE name = 'SMTP_HOST';
DELETE FROM settings WHERE name = 'SMTP_PORT';
DELETE FROM settings WHERE name = 'SMTP_USER';
DELETE FROM settings WHERE name = 'SMTP_PASSWORD';
DELETE FROM settings WHERE name = 'SMTP_SENDER';

DELETE FROM settings WHERE name = 'EMAIL_VERIFICATION_SUBJECT';
DELETE FROM settings WHERE name = 'EMAIL_VERIFICATION_REDIRECT_URL';
DELETE FROM settings WHERE name = 'EMAIL_VERIFICATION_BODY';

DELETE FROM settings WHERE name = 'PASSWORD_RESET_SUBJECT';
DELETE FROM settings WHERE name = 'PASSWORD_RESET_REDIRECT_URL';
DELETE FROM settings WHERE name = 'PASSWORD_RESET_BODY';

DELETE FROM settings WHERE name = 'MFA_VERIFICATION_SUBJECT';
DELETE FROM settings WHERE name = 'MFA_VERIFICATION_REDIRECT_URL';
DELETE FROM settings WHERE name = 'MFA_VERIFICATION_BODY';

-- +goose StatementEnd
