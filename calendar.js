// calendar.js
import express from 'express';
import db from './db.js'; // Make sure db.js is in the root folder

const router = express.Router();

// GET consultations for a user
// Returns all consultations with their status for the calendar
router.get('/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const [rows] = await db.execute(
      'SELECT id, date, time, status FROM consultations WHERE user_id = ?',
      [userId]
    );
    res.json({ success: true, consultations: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to fetch consultations' });
  }
});

// PUT update consultation status
// Update status to "missed", "visited", or "appointment"
router.put('/status/:consultationId', async (req, res) => {
  const { consultationId } = req.params;
  const { status } = req.body;

  if (!['missed', 'visited', 'appointment'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status value' });
  }

  try {
    await db.execute(
      'UPDATE consultations SET status = ? WHERE id = ?',
      [status, consultationId]
    );
    res.json({ success: true, message: 'Status updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to update status' });
  }
});

export default router;
