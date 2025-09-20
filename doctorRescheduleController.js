// doctorRescheduleController.js
import pool from './db.js'; // Make sure your db.js exports the MySQL pool

// ---------------- RESCHEDULE CONSULTATION ----------------
export const rescheduleConsultation = async (consultation_id, newDate, newTime) => {
  try {
    // Check if consultation exists
    const [rows] = await pool.query(
      'SELECT * FROM consultations WHERE id = ?',
      [consultation_id]
    );

    if (rows.length === 0) {
      return { success: false, message: 'Consultation not found.' };
    }

    // Update the consultation date and time
    await pool.query(
      'UPDATE consultations SET date = ?, time = ? WHERE id = ?',
      [newDate, newTime, consultation_id]
    );

    return { success: true, message: 'Consultation rescheduled successfully.' };
  } catch (err) {
    console.error(err);
    return { success: false, message: 'Database error.' };
  }
};
