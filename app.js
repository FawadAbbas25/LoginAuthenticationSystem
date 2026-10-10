
const registerForm = document.getElementById("registerForm");
const loginForm = document.getElementById("loginForm");

function showMessage(message, isError = true) {
  const element = document.getElementById("message");

  if (element) {
    element.textContent = message;
    element.className = isError
      ? "message error"
      : "message success";
  }
}

async function sendRequest(url, data) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "same-origin",
    body: JSON.stringify(data)
  });

  const result = await response.json();
  return { response, result };
}

// Registration
if (registerForm) {
  registerForm.addEventListener("submit", async event => {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    if (!username || !email || !password) {
      return showMessage("Please fill in all fields.");
    }

    if (password.length < 8 || !/[0-9]/.test(password)) {
      return showMessage(
        "Password must have at least 8 characters and 1 number."
      );
    }

    try {
      const { response, result } = await sendRequest(
        "/api/register",
        { username, email, password }
      );

      showMessage(result.message, !response.ok);

      if (response.ok) {
        registerForm.reset();
        setTimeout(() => {
          window.location.href = "/login.html";
        }, 1000);
      }
    } catch {
      showMessage("Unable to connect to the server.");
    }
  });
}

// Login
if (loginForm) {
  loginForm.addEventListener("submit", async event => {
    event.preventDefault();

    const identifier =
      document.getElementById("identifier").value.trim();
    const password =
      document.getElementById("password").value;

    if (!identifier || !password) {
      return showMessage("Please fill in both fields.");
    }

    try {
      const { response, result } = await sendRequest(
        "/api/login",
        { identifier, password }
      );

      if (!response.ok) {
        return showMessage(result.message);
      }

      window.location.replace(result.redirect);
    } catch {
      showMessage("Unable to connect to the server.");
    }
  });
}
