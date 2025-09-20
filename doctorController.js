// doctorController.js
import db from './db.js';
import bcrypt from 'bcrypt';

// Doctor Signup
export async function signupDoctor(name, email, password, center, specialization) {
  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = 'INSERT INTO doctors (name, email, password, center, specialization) VALUES (?, ?, ?, ?, ?)';
  return new Promise((resolve, reject) => {
    db.query(sql, [name, email, hashedPassword, center, specialization], (err, result) => {
      if (err) return reject(err);
      console.log('Doctor registered successfully!');
      resolve(result);
    });
  });
}

// Doctor Login
export async function loginDoctor(email, password) {
  const sql = 'SELECT * FROM doctors WHERE email = ?';
  return new Promise((resolve, reject) => {
    db.query(sql, [email], async (err, results) => {
      if (err) return reject(err);

      if (results.length === 0) {
        resolve(null); // Doctor not found
        return;
      }

      const doctor = results[0];
      const isMatch = await bcrypt.compare(password, doctor.password);

      if (isMatch) {
        resolve(doctor); // Successful login
      } else {
        resolve(null); // Invalid password
      }
    });
  });
}
