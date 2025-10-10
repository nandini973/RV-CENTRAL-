const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public')); // Serve static files

// MySQL Database Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'rv_central'
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  }
  console.log('Connected to MySQL database');
  
  // Create users table
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      course VARCHAR(100) NOT NULL,
      year VARCHAR(50) NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  
  // Create admins table
  const createAdminsTable = `
    CREATE TABLE IF NOT EXISTS admins (
      id INT AUTO_INCREMENT PRIMARY KEY,
      admin_username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role ENUM('lead', 'president') NOT NULL,
      club VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  
  db.query(createUsersTable, (err) => {
    if (err) console.error('Error creating users table:', err);
    else console.log('Users table ready');
  });
  
  db.query(createAdminsTable, (err) => {
    if (err) console.error('Error creating admins table:', err);
    else console.log('Admins table ready');
  });
});

// ============ USER SIGNUP ============
app.post('/api/user/signup', async (req, res) => {
  try {
    const { username, course, year, password, confirm_password } = req.body;

    // Validation
    if (!username || !course || !year || !password || !confirm_password) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }

    // Check if passwords match
    if (password !== confirm_password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Passwords do not match' 
      });
    }

    // Password strength validation
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Check if user already exists
    const checkUserQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(checkUserQuery, [username], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Server error' 
        });
      }

      if (results.length > 0) {
        return res.status(409).json({ 
          success: false, 
          message: 'Username already exists' 
        });
      }

      // Hash password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Insert new user
      const insertQuery = 'INSERT INTO users (username, course, year, password) VALUES (?, ?, ?, ?)';
      db.query(insertQuery, [username, course, year, hashedPassword], (err, result) => {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Failed to create account' 
          });
        }

        res.status(201).json({ 
          success: true, 
          message: 'Account created successfully',
          userId: result.insertId
        });
      });
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// ============ USER LOGIN ============
app.post('/api/user/login', (req, res) => {
  try {
    const { username, course, year, password } = req.body;

    // Validation
    if (!username || !course || !year || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }

    // Find user
    const query = 'SELECT * FROM users WHERE username = ? AND course = ? AND year = ?';
    db.query(query, [username, course, year], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Server error' 
        });
      }

      if (results.length === 0) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid credentials' 
        });
      }

      const user = results[0];

      // Compare password
      const passwordMatch = await bcrypt.compare(password, user.password);
      
      if (!passwordMatch) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid credentials' 
        });
      }

      // Successful login
      res.status(200).json({ 
        success: true, 
        message: 'Login successful',
        user: {
          id: user.id,
          username: user.username,
          course: user.course,
          year: user.year,
          type: 'user'
        }
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// ============ ADMIN LOGIN ============
app.post('/api/admin/login', (req, res) => {
  try {
    const { admin_username, admin_password, role, club } = req.body;

    // Validation
    if (!admin_username || !admin_password || !role || !club) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }

    // Find admin
    const query = 'SELECT * FROM admins WHERE admin_username = ? AND role = ? AND club = ?';
    db.query(query, [admin_username, role, club], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false, 
          message: 'Server error' 
        });
      }

      if (results.length === 0) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid admin credentials' 
        });
      }

      const admin = results[0];

      // Compare password
      const passwordMatch = await bcrypt.compare(admin_password, admin.password);
      
      if (!passwordMatch) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid admin credentials' 
        });
      }

      // Successful login
      res.status(200).json({ 
        success: true, 
        message: 'Admin login successful',
        admin: {
          id: admin.id,
          username: admin.admin_username,
          role: admin.role,
          club: admin.club,
          type: 'admin'
        }
      });
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// ============ ADMIN SIGNUP (Optional - for creating admin accounts) ============
app.post('/api/admin/signup', async (req, res) => {
  try {
    const { admin_username, admin_password, role, club } = req.body;

    if (!admin_username || !admin_password || !role || !club) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Check if admin exists
    const checkQuery = 'SELECT * FROM admins WHERE admin_username = ?';
    db.query(checkQuery, [admin_username], async (err, results) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Server error' });
      }

      if (results.length > 0) {
        return res.status(409).json({ 
          success: false, 
          message: 'Admin username already exists' 
        });
      }

      const hashedPassword = await bcrypt.hash(admin_password, 10);
      const insertQuery = 'INSERT INTO admins (admin_username, password, role, club) VALUES (?, ?, ?, ?)';
      
      db.query(insertQuery, [admin_username, hashedPassword, role, club], (err, result) => {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ 
            success: false, 
            message: 'Failed to create admin account' 
          });
        }

        res.status(201).json({ 
          success: true, 
          message: 'Admin account created successfully'
        });
      });
    });
  } catch (error) {
    console.error('Admin signup error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Test endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running', timestamp: new Date() });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log(`API endpoints available at http://localhost:${PORT}/api`);
});