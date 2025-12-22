<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Secure Lab Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>

  <!-- نفس ملفك -->
  <link rel="stylesheet" href="${url.resourcesPath}/css/login.css">
</head>

<body>
  <div class="bg-orbs" aria-hidden="true"></div>

  <div class="login-container">
    <div class="login-card">

      <div class="brand">
        <img src="${url.resourcesPath}/img/logo.png" class="logo" alt="Secure Lab Logo" />
        <div class="brand-text">
          <h1 class="brand-title">Secure Library</h1>
          <p class="brand-subtitle">Human Security Management System</p>
        </div>
      </div>

      <h2 class="login-title">Sign in</h2>

      <#-- ✅ رسالة Keycloak لو في خطأ (username/password غلط) -->
      <#if message?? && message.summary??>
        <div class="alert ${message.type!''}">
          ${message.summary?no_esc}
        </div>
      </#if>

      <form action="${url.loginAction}" method="post" class="login-form">
        <label class="field">
          <span class="field-label">Username</span>
          <input type="text" name="username" placeholder="Enter your username" autocomplete="username" required />
        </label>

        <label class="field">
          <span class="field-label">Password</span>
          <input type="password" name="password" placeholder="Enter your password" autocomplete="current-password" required />
        </label>

        <button type="submit" class="btn btn-primary">
          Log In
        </button>
      </form>

      <p class="footer-text">Secured Library System</p>
    </div>
  </div>
</body>
</html>
