// userController.js
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

// 1️⃣ Create a MySQL connection
export async function getConnection() {
  return await mysql.createConnection({
    host: 'localhost',
    user: 'prakritipath_user',       // your MySQL username
    password: 'StrongPassword123!',  // your MySQL password
    database: 'prakritipath'         // your database name
  });
}

// 2️⃣ Signup function
export async function signup(name, email, password) {
  const connection = await getConnection();
  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.execute(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    console.log('User registered successfully!');
  } catch (err) {
    console.error('Error during signup:', err);
    throw err;
  } finally {
    await connection.end();
  }
}

// 3️⃣ Login function
export async function login(email, password) {
  const connection = await getConnection();
  try {
    // ✅ Use specific columns and correct primary key
    const [rows] = await connection.execute(
      'SELECT user_id, name, email, password FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      throw new Error('User not found');
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new Error('Incorrect password');
    }

    console.log('User logged in successfully!');

    // ✅ Return correct user_id for frontend
    return {
      user_id: user.user_id,  // matches your users table primary key
      name: user.name,
      email: user.email
    };
  } catch (err) {
    console.error('Error during login:', err);
    throw err;
  } finally {
    await connection.end();
  }
}
