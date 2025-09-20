import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

// --- 1. MySQL connection function ---
export async function getConnection() {
  return await mysql.createConnection({
    host: 'localhost',
    user: 'prakritipath_user',       // your MySQL username
    password: 'StrongPassword123!',  // your MySQL password
    database: 'prakritipath'         // your database
  });
}

// --- 2. Existing signup function ---
export async function signup(name, email, password) {
  const connection = await getConnection();
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await connection.execute(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );
    console.log('User registered successfully!');
  } finally {
    await connection.end();
  }
}

// --- 3. NEW login function ---
export async function login(email, password) {
  const connection = await getConnection();
  try {
    // Check if user exists
    const [rows] = await connection.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      throw new Error('User not found');
    }

    const user = rows[0];

    // Compare password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new Error('Invalid password');
    }

    // Return user data (without password)
    return { id: user.id, name: user.name, email: user.email };
  } finally {
    await connection.end();
  }
}
