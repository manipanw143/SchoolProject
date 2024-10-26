const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const secretKey = 'your-secret-key';
const multer = require('multer');
const path = require('path');
const fs = require('fs');


// Middleware to parse JSON bodies and enable CORS
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:3001'
}));

// MySQL connection setup
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'pass@123', // Use your MySQL password
    database: 'schoolpj'
});


db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});




// Parent login route
app.post('/login', async (req, res) => {
    const { gmail, password } = req.body;
  
    const sql = 'SELECT * FROM parent WHERE gmail = ?';
    db.query(sql, [gmail], async (err, results) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (results.length === 0) return res.status(400).json({ error: 'Parent not found' });
  
      const parent = results[0];
  
      // Check password
      const validPassword = await bcrypt.compare(password, parent.password);
      if (!validPassword) return res.status(400).json({ error: 'Invalid password' });
  
      // Generate a token
      const token = jwt.sign({ parentId: parent.id }, secretKey, { expiresIn: '1h' });
      res.status(200).json({ token });
    });
  });
  
  // Middleware to verify the token
  const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Access denied' });
  
    try {
      const decoded = jwt.verify(token, secretKey);
      req.parentId = decoded.parentId;
      next();
    } catch (err) {
      res.status(400).json({ error: 'Invalid token' });
    }
  };
  
  // Route to get parent's own data
  app.get('/parent/me', verifyToken, (req, res) => {
    const sql = 'SELECT * FROM parent WHERE id = ?';
    db.query(sql, [req.parentId], (err, result) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch parent data' });
      res.status(200).json(result[0]);
    });
  });



  app.post('/school', async (req, res) => {
    const { gmail, password } = req.body;

    if (!gmail || !password) {
        return res.status(400).json({ error: 'Gmail, and password are required' });
    }

    try {
        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = 'INSERT INTO school (gmail, password) VALUES (?, ?)';
        db.query(sql, [gmail, hashedPassword], (err, result) => {
            if (err) {
                console.error('Error inserting data:', err);
                return res.status(500).json({ error: 'Failed to add school' });
            }
            // Send a response with a message and inserted ID
            res.status(201).json({ message: 'School added successfully', id: result.insertId });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});


app.get('/school', (req, res) => {
    const sql = 'SELECT * FROM school';
    db.query(sql, (err, result) => {
        if (err) {
            console.error('Error fetching School:', err);
            return res.status(500).json({ error: 'Failed to fetch School' });
        }
        res.status(200).json(result);  // Send back the students data
    });
});

 //  SCHOOL LOGIN ----->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

 app.post('/school-login', async (req, res) => {
    const { gmail, password } = req.body;
    try {
        const sql = 'SELECT * FROM school WHERE gmail = ?';
        db.query(sql, [gmail], async (err, results) => {
            if (err) {
                console.error('Database query error:', err); // Log the error
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.length === 0) {
                return res.status(400).json({ error: 'School not found' });
            }

            const school = results[0];
            const validPassword = await bcrypt.compare(password, school.password);
            if (!validPassword) {
                return res.status(400).json({ error: 'Invalid password' });
            }

            const token = jwt.sign({ schoolId: school.id }, secretKey, { expiresIn: '1h' });
            res.status(200).json({ token });
        });
    } catch (error) {
        console.error('Unexpected error:', error); // Log the unexpected error
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Middleware to verify the token
const verifySchoolToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Ensure to split token from "Bearer token"
    if (!token) return res.status(401).json({ error: 'Access denied' });

    try {
        const decoded = jwt.verify(token, secretKey);
        req.schoolId = decoded.schoolId; // Use correct property name
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Route to get school data
app.get('/school/me', verifySchoolToken, (req, res) => {
    const sql = 'SELECT * FROM school WHERE id = ?';
    db.query(sql, [req.schoolId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch school data' });
        res.status(200).json(result[0]);
    });
});


app.post('/parent', async (req, res) => {
    const { name, student_name, mobile_number, address, gmail, password } = req.body;

    if (!name || !gmail || !password) {
        return res.status(400).json({ error: 'Name, Gmail, and password are required' });
    }

    try {
        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = 'INSERT INTO parent (name, student_name, mobile_number, address, gmail, password) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(sql, [name, student_name, mobile_number, address, gmail, hashedPassword], (err, result) => {
            if (err) {
                console.error('Error inserting data:', err);
                return res.status(500).json({ error: 'Failed to add parent' });
            }
            // Send a response with a message and inserted ID
            res.status(201).json({ message: 'Parent added successfully', id: result.insertId });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});


app.put('/parent/:id', (req, res) => {
    const { id } = req.params;
    const { name, student_name, mobile_number, address, gmail } = req.body;

    // Check if id is a valid number
    if (isNaN(id)) {
        return res.status(400).json({ message: 'Invalid ID format' });
    }

    const sql = 'UPDATE parent SET name = ?, student_name = ?, mobile_number = ?, address = ?, gmail = ? WHERE id = ?';
    db.query(sql, [name, student_name, mobile_number, address, gmail, id], (err, result) => {
        if (err) {
            console.error('Error updating parent:', err);
            return res.status(500).json({ message: 'Failed to update parent', error: err });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Parent updated successfully' });
        } else {
            res.status(404).json({ message: 'Parent not found' });
        }
    });
});

app.delete('/parent/:id', (req, res) => {
    const { id } = req.params;

    // Check if id is a valid number
    if (isNaN(id)) {
        return res.status(400).json({ message: 'Invalid ID format' });
    }
    
    // Delete the parent from the database
    const query = 'DELETE FROM parent WHERE id = ?';
    db.query(query, [id], (err, result) => {
        if (err) {
            console.error('Error deleting parent:', err);
            return res.status(500).json({ message: 'Failed to delete parent', error: err });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Parent deleted successfully' });
        } else {
            res.status(404).json({ message: 'Parent not found' });
        }
    });
});


app.get('/parent', (req, res) => {
    const sql = 'SELECT * FROM parent';
    db.query(sql, (err, result) => {
        if (err) {
            console.error('Error fetching Parents:', err);
            return res.status(500).json({ error: 'Failed to fetch Parent' });
        }
        res.status(200).json(result);  // Send back the students data
    });
});



// Update student by ID
app.put('/student/:id', async (req, res) => {
    const { id } = req.params;
    const { name, age } = req.body;
  
    try {
      const sql = `UPDATE student SET name = ?, age = ? WHERE id = ?`;
      const values = [name, age, id];
  
      db.query(sql, values, (err, result) => {
        if (err) {
          console.error('Error updating student:', err);
          return res.status(500).json({ message: 'Failed to update student', error:err });
        }
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: 'Student not found' });
        }

        res.status(200).json({ message: 'Student updated successfully' });
      });
    } catch (error) {
      console.error('Error in update student route:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  });
  

 // Route to insert a student's name
app.post('/student', (req, res) => {
    const { name, age } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Student name is required' });
    }

    const sql = 'INSERT INTO student (name, age) VALUES (?, ?)';
    db.query(sql, [name, age || null], (err, result) => {
        if (err) {
            console.error('Error inserting data:', err);
            return res.status(500).json({ error: 'Failed to add student' });
        }
        // Send a response with a message and inserted ID
        res.status(201).json({ message: 'Student added successfully', id: result.insertId });
    });
}); 

app.get('/student', (req, res) => {
    const sql = 'SELECT * FROM student';
    db.query(sql, (err, result) => {
        if (err) {
            console.error('Error fetching students:', err);
            return res.status(500).json({ error: 'Failed to fetch students' });
        }
        res.status(200).json(result);  // Send back the students data
    });
});

// Set up storage engine for multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Store images in the 'uploads' directory
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

// Initialize multer with the storage engine and file filter
const upload = multer({
    storage: storage,
    limits: { fileSize: 1000000 }, // Limit file size to 1MB
    fileFilter: (req, file, cb) => {
        const fileTypes = /jpeg|jpg|png/; // Allow only these file types
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = fileTypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb('Error: Images only!');
        }
    }
});

// CREATE Peon (POST with image upload)
app.post('/peon', upload.single('image'), (req, res) => {
    const { name, mobile_number, start_time, end_time, from_date, last_date } = req.body;
    const image = req.file ? req.file.filename : null; // Store image file name

    if (!name || !mobile_number || !start_time || !end_time || !from_date || !last_date) {
        return res.status(400).json({ error: 'All fields except image are required' });
    }

    const sql = 'INSERT INTO peon (name, mobile_number, start_time, end_time, from_date, last_date, image) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, mobile_number, start_time, end_time, from_date, last_date, image], (err, result) => {
        if (err) {
            console.error('Error inserting data:', err);
            return res.status(500).json({ error: 'Failed to add peon' });
        }
        res.status(201).json({ message: 'Peon added successfully', id: result.insertId });
    });
});


// UPDATE Peon (PUT with optional image upload)


app.put('/peon/:id', upload.single('image'), (req, res) => {
    const { name, mobile_number, start_time, end_time, from_date, last_date } = req.body;
    const image = req.file ? req.file.filename : null; // Store image file name if provided
    const { id } = req.params;

    // Convert from_date and last_date to YYYY-MM-DD format
    const formattedFromDate = new Date(from_date).toISOString().split('T')[0];
    const formattedLastDate = new Date(last_date).toISOString().split('T')[0];

    // First, check if the peon exists
    const checkSql = 'SELECT image FROM peon WHERE id = ?';
    db.query(checkSql, [id], (err, results) => {
        if (err) {
            console.error('Error fetching peon data:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Peon not found' });
        }

        const existingImage = results[0].image;

        // Construct the SQL query to update the peon data
        const updateSql = `
            UPDATE peon
            SET name = ?, mobile_number = ?, start_time = ?, end_time = ?, from_date = ?, last_date = ?, image = COALESCE(?, image)
            WHERE id = ?
        `;

        db.query(updateSql, [name, mobile_number, start_time, end_time, formattedFromDate, formattedLastDate, image, id], (err, result) => {
            if (err) {
                console.error('Error updating peon data:', err);
                return res.status(500).json({ error: 'Failed to update peon' });
            }

            // If a new image is uploaded, delete the old image from the server
            if (image && existingImage) {
                const oldImagePath = path.join(__dirname, 'uploads', existingImage);
                fs.unlink(oldImagePath, (err) => {
                    if (err) {
                        console.error('Error deleting old image:', err);
                    }
                });
            }

            res.status(200).json({ message: 'Peon updated successfully' });
        });
    });
});



// DELETE Peon (including image)
app.delete('/peon/:id', (req, res) => {
    const { id } = req.params;

    // First, fetch the peon data to check if they exist and retrieve the image file name
    const selectSql = 'SELECT image FROM peon WHERE id = ?';
    db.query(selectSql, [id], (err, results) => {
        if (err) {
            console.error('Error fetching peon data:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Peon not found' });
        }

        const image = results[0].image;

        // Now, delete the peon from the database
        const deleteSql = 'DELETE FROM peon WHERE id = ?';
        db.query(deleteSql, [id], (err, result) => {
            if (err) {
                console.error('Error deleting peon:', err);
                return res.status(500).json({ error: 'Failed to delete peon' });
            }

            // If an image exists, delete it from the server
            if (image) {
                const imagePath = path.join(__dirname, 'uploads', image);
                fs.unlink(imagePath, (err) => {
                    if (err) {
                        console.error('Error deleting image:', err);
                    }
                });
            }

            res.status(200).json({ message: 'Peon deleted successfully' });
        });
    });
});

// Get all peons (GET)

app.get('/peon', (req, res) => {
    const sql = 'SELECT id, name, mobile_number, start_time, end_time, DATE_FORMAT(from_date, "%Y-%m-%d") as from_date, DATE_FORMAT(last_date, "%Y-%m-%d") as last_date FROM peon';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching peons:', err);
            return res.status(500).json({ error: 'Failed to fetch peons' });
        }
        res.status(200).json(results);
    });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
