// consultationController.js
import pool from './db.js';

// ---------------- BOOK CONSULTATION ----------------
export const bookConsultation = async (user_id, doctor_id, date, time, reason) => {
  try {
    // Optional: Check if doctor exists
    const [doctorRows] = await pool.query('SELECT * FROM doctors WHERE id = ?', [doctor_id]);
    if (doctorRows.length === 0) {
      return { success: false, message: 'Doctor not found.' };
    }

    // Insert consultation
    const [result] = await pool.query(
      'INSERT INTO consultations (user_id, doctor_id, date, time, reason) VALUES (?, ?, ?, ?, ?)',
      [user_id, doctor_id, date, time, reason]
    );

    return { success: true, consultationId: result.insertId };
  } catch (err) {
    console.error(err);
    return { success: false, message: 'Database error.' };
  }
};

// ---------------- GET USER CONSULTATIONS ----------------
export const getUserConsultations = async (user_id) => {
  try {
    const [rows] = await pool.query(
      `SELECT c.id, c.date, c.time, c.reason, d.name AS doctor_name, d.specialization 
       FROM consultations c
       JOIN doctors d ON c.doctor_id = d.id
       WHERE c.user_id = ? 
       ORDER BY c.date DESC, c.time DESC`,
      [user_id]
    );
    return rows;
  } catch (err) {
    console.error(err);
    throw err;
  }
};
