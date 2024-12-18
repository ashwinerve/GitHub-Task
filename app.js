import { Hono } from "https://deno.land/x/hono/mod.ts";
import client from "./db/db.js";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";

const app = new Hono();

app.use("*", async (c, next) => {
  c.header(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none';"
  );
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  await next();
});

app.get('/register', async (c) => {
  return c.html(await Deno.readTextFile('./views/register.html'));
});

// Validate username (must be a valid email address)
function validateInput({ username, password, role }) {
  // Regular expression to match a valid email format
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const validRoles = ["reserver", "administrator"];

  console.log("Validating Input:", { username, password, role });

  return (
    emailRegex.test(username) &&  // Validate username as email
    password.length >= 8 &&  // Validate password length
    validRoles.includes(role)  // Validate role
  );
}

app.post('/register', async (c) => {
  try {
    const body = await c.req.parseBody();
    const username = body.username;
    const password = body.password;
    const role = body.role;
    const birthdate = body.birthdate || "1900-01-01"; // Default to a generic date if not provided

    console.log("Received Input:", { username, password, role, birthdate });

    if (!validateInput({ username, password, role })) {
      return c.text('Invalid input data. Please try again.', 400);
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    try {
      // Insert the user into the database with a default birthdate if not provided
      await client.queryArray(
        `INSERT INTO zephyr_users (username, password_hash, role, birthdate)
         VALUES ($1, $2, $3, $4)`,
        [username, hashedPassword, role, birthdate]
      );
      return c.text('User registered successfully!');
    } catch (dbError) {
      console.error("Database Error:", dbError);
      return c.text('Database error. Please try again later.', 500);
    }
  } catch (error) {
    console.error("Error during registration:", error);
    return c.text('Error during registration. Please try again later.', 500);
  }
});

Deno.serve(app.fetch);
