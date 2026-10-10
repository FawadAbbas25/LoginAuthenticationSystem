
const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = 3000;

const USERS_FILE = path.join(__dirname, "users.json");
const PUBLIC_DIR = path.join(__dirname, "public");
const DASHBOARD_FILE = path.join(__dirname, "views", "dashboard.html");

if (
  process.env.NODE_ENV === "production" &&
  !process.env.SESSION_SECRET
) {
  throw new Error("SESSION_SECRET must be set in production.");
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    name: "auth.sid",
    secret:
      process.env.SESSION_SECRET ||
      "development-only-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 60 * 60 * 1000
    }
  })
);

// Serve public files only.
app.use(express.static(PUBLIC_DIR));

async function readUsers() {
  try {
    return JSON.parse(
      await fs.readFile(USERS_FILE, "utf8")
    );
  } catch (error) {
    if (error.code === "ENOENT") {
      await fs.writeFile(USERS_FILE, "[]");
      return [];
    }

    throw error;
  }
}

async function writeUsers(users) {
  await fs.writeFile(
    USERS_FILE,
    JSON.stringify(users, null, 2)
  );
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      message: "Please log in to access this page."
    });
  }

  next();
}

// Home and page routes
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "register.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "login.html"));
});

// Register a new user
app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const password = req.body.password;

    if (
      !username ||
      username.length > 50 ||
      !email ||
      email.length > 254 ||
      typeof password !== "string" ||
      !password
    ) {
      return res.status(400).json({
        message: "Please fill in all required fields."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        message: "Please enter a valid email address."
      });
    }

    if (password.length < 8 || !/[0-9]/.test(password)) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters and contain at least 1 number."
      });
    }

    const users = await readUsers();

    const exists = users.some(
      user =>
        user.username.toLowerCase() === username.toLowerCase() ||
        user.email === email
    );

    if (exists) {
      return res.status(409).json({
        message: "That username or email is already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const newUser = {
      id: crypto.randomUUID(),
      username,
      email,
      passwordHash
    };

    users.push(newUser);
    await writeUsers(users);

    return res.status(201).json({
      message: "Registration successful. You can now log in."
    });
  } catch (error) {
    console.error("Registration error:", error);

    return res.status(500).json({
      message: "Something went wrong. Please try again."
    });
  }
});

// Log in
app.post("/api/login", async (req, res) => {
  try {
    const identifier = String(req.body.identifier || "")
      .trim()
      .toLowerCase();
    const password = req.body.password;

    if (
      !identifier ||
      typeof password !== "string" ||
      !password
    ) {
      return res.status(400).json({
        message: "Please enter your username/email and password."
      });
    }

    const users = await readUsers();

    const user = users.find(
      item =>
        item.username.toLowerCase() === identifier ||
        item.email === identifier
    );

    if (!user) {
      return res.status(401).json({
        message: "Invalid username/email or password."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid username/email or password."
      });
    }

    // Regenerate the session after successful login.
    req.session.regenerate(error => {
      if (error) {
        console.error("Session error:", error);

        return res.status(500).json({
          message: "Unable to start your session."
        });
      }

      req.session.userId = user.id;

      req.session.save(error => {
        if (error) {
          console.error("Session save error:", error);

          return res.status(500).json({
            message: "Unable to start your session."
          });
        }

        return res.json({
          message: "Login successful.",
          redirect: "/dashboard"
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      message: "Something went wrong. Please try again."
    });
  }
});

// Protected dashboard
app.get("/dashboard", requireLogin, (req, res) => {
  res.sendFile(DASHBOARD_FILE);
});

// Return the logged-in user's public details
app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const users = await readUsers();

    const user = users.find(
      item => item.id === req.session.userId
    );

    if (!user) {
      return res.status(401).json({
        message: "User account not found. Please log in again."
      });
    }

    return res.json({
      id: user.id,
      username: user.username,
      email: user.email
    });
  } catch (error) {
    console.error("Get user error:", error);

    return res.status(500).json({
      message: "Unable to retrieve user details."
    });
  }
});

// Log out
app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy(error => {
    if (error) {
      console.error("Logout error:", error);

      return res.status(500).json({
        message: "Unable to log out. Please try again."
      });
    }

    res.clearCookie("auth.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/"
    });

    return res.json({
      message: "Logged out successfully.",
      redirect: "/login.html"
    });
  });
});

app.listen(PORT, () => {
  console.log(`Authentication app running at http://localhost:${PORT}`);
});
