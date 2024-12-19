import { Hono } from "https://deno.land/x/hono/mod.ts";
import client from "./db/db.js";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts"; // For password hashing
import { createHash } from "https://deno.land/std@0.114.0/hash/mod.ts"; // For pseudonymization

const app = new Hono();

// Set Content Security Policy (CSP) headers with no wildcard directive
const cspHeaders = {
  "Content-Security-Policy": [
    "default-src 'self';", // Only allow content from the same origin
    "script-src 'self';", // Only allow scripts from the same origin
    "style-src 'self';", // Only allow styles from the same origin
    "img-src 'self';", // Only allow images from the same origin
    "font-src 'self';", // Only allow fonts from the same origin
    "object-src 'none';", // Prevent embedding objects like Flash
    "connect-src 'self';", // Only allow connections to the same origin (e.g., for APIs)
    "frame-ancestors 'none';", // Prevent framing of the page (to mitigate clickjacking)
    "base-uri 'self';", // Restrict <base> tag to the same origin
    "form-action 'self';", // Only allow form submissions to the same origin
    "child-src 'none';", // Disable child frames
    "worker-src 'none';", // Disable web workers
    "manifest-src 'self';" // Restrict manifest files to the same origin
  ].join(' '),
  "X-Frame-Options": "DENY", // Anti-clickjacking
  "X-Content-Type-Options": "nosniff", // Prevent MIME-type sniffing
};

// Middleware to apply security headers to all responses
app.use('*', (c, next) => {
  c.header("Content-Security-Policy", cspHeaders["Content-Security-Policy"]);
  c.header("X-Frame-Options", cspHeaders["X-Frame-Options"]);
  c.header("X-Content-Type-Options", cspHeaders["X-Content-Type-Options"]);
  return next();
});

// Serve static files (like styles.css)
app.get('/static/*', async (c) => {
  const path = c.req.path.replace('/static', '');
  try {
    const file = await Deno.readFile(`./static${path}`);
    const contentType = path.endsWith('.css') ? 'text/css' : 'application/octet-stream';
    return c.body(file, 200, { "Content-Type": contentType });
  } catch (error) {
    console.error("Error loading static file:", error);
    return c.text('Static file not found', 404);
  }
});

// Serve the index page
app.get('/', async (c) => {
  try {
    return c.html(await Deno.readTextFile('./views/index.html'));
  } catch (error) {
    console.error("Error loading index.html:", error);
    return c.text('Error loading the home page', 500);
  }
});

// Serve the registration form
app.get('/register', async (c) => {
  try {
    return c.html(await Deno.readTextFile('./views/register.html'));
  } catch (error) {
    console.error("Error loading register.html:", error);
    return c.text('Error loading the registration page', 500);
  }
});

// Handle user registration (form submission)
app.post('/register', async (c) => {
  const body = await c.req.parseBody();
  const username = body.username;
  const password = body.password;
  const role = body.role;

  try {
    // Validate input
    if (!username || !password || !role) {
      return c.text('Invalid input data. Please try again.', 400);
    }

    if (!/^\S+@\S+\.\S+$/.test(username)) {
      return c.text('Invalid email format.', 400);
    }

    if (password.length < 8) {
      return c.text('Password must be at least 8 characters long.', 400);
    }

    // Hash the user's password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insert the new user into the database
    await client.queryArray(
      "INSERT INTO zephyr_users (username, password_hash, role) VALUES ($1, $2, $3)",
      [username, hashedPassword, role]
    );

    return c.text('User registered successfully!');
  } catch (error) {
    console.error(error);
    return c.text('Error during registration', 500);
  }
});

// Serve the login form
app.get('/login', async (c) => {
  try {
    return c.html(await Deno.readTextFile('./views/login.html'));
  } catch (error) {
    console.error("Error loading login.html:", error);
    return c.text('Error loading the login page', 500);
  }
});

// Handle login submission
app.post('/login', async (c) => {
  const body = await c.req.parseBody();
  const username = body.username;
  const password = body.password;

  try {
    // Fetch the user from the database
    const result = await client.queryObject(
      "SELECT * FROM zephyr_users WHERE username = $1",
      [username]
    );
    const user = result.rows[0];

    if (!user) {
      return c.text('Invalid username or password', 401);
    }

    // Compare the password with the stored hash
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return c.text('Invalid username or password', 401);
    }

    // Generate a pseudonym for GDPR compliance
    const hash = createHash('sha256');
    hash.update(username);
    const pseudonym = hash.toString();

    // Log the successful login
    await client.queryArray(
      "INSERT INTO login_logs (pseudonym) VALUES ($1)",
      [pseudonym]
    );

    return c.text('Login successful!');
  } catch (error) {
    console.error(error);
    return c.text('An error occurred during login', 500);
  }
});

// The Web app starts with the command:
// deno run --allow-net --allow-env --allow-read --watch app.js

Deno.serve(app.fetch);
