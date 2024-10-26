const express = require('express');
const router = express.Router();
const db = require('../config/database'); // assuming you have a database config file

// Route to fetch student data
router.get('/students', (req, res) => {
  const query = 'SELECT * FROM students'; // Query to get all students from the table
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query failed' });
    }
    res.json(results); // Send the data as a JSON response
  });
});

module.exports = router;
