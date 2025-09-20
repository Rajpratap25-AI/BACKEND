// db.js
import mysql from 'mysql2/promise';

const db = mysql.createPool({
  host: 'localhost',
  user: 'prakritipath_user',        // your MySQL username
  password: 'StrongPassword123!',   // your MySQL password
  database: 'prakritipath',         // your database name
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

console.log('MySQL pool created successfully');

export default db;
