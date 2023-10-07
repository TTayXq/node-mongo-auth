const express = require('express')
const app = express();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const port = 3000;

mongoose.connect('mongodb+srv://admin:1234@cluster0.ox5spyr.mongodb.net/?retryWrites=true&w=majority', { useNewUrlParser: true });

app.use(express.json());

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });

const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String,
             required: true, 
             unique: true,
             match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
             },
    password: { type: String, 
                required: true,
                minlength: 8,
                match: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/,
                },
    createAt: { type: Date, default: Date.now },
    lastLogin: { type: Date, default: null },
  });

  const User = mongoose.model('User', userSchema);

  // Create User Endpoint
  app.post('/users/create', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName) {
      return res.status(400).json({ error: 'Missing FirstName plase provide FirstName' });
    } else if (!lastName) {
      return res.status(400).json({ error: 'Missing LastName plase provide LastName' });
    } else if (!email) {
      return res.status(400).json({ error: 'Missing Email plase provide Email' });
    }else if (!password) {
      return res.status(400).json({ error: 'Missing Password plase provide Password' });
    }

    // Validate password format
    const passwordFormatRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    if (!passwordFormatRegex.test(password)) {
    return res.status(400).json({ error: 'Invalid password format' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ firstName, lastName, email, password: hashedPassword });

    try {
        await newUser.save();
        res.status(201).json({ message: 'Create user successfully' });
      } catch (error) {
        if (error.errors && error.errors.email) {
          // Mongoose validation error for email
          res.status(400).json({ error: 'Invalid email format' });
        } else if (error.errors && error.errors.password) {
          // Mongoose validation error for password
          res.status(400).json({ error: 'Invalid password format' });
        } else if (error.code === 11000 && error.keyPattern.email) {
          // Duplicate key error, i.e., email already exists
          res.status(400).json({ error: 'Email is already taken' });
        } else {
          console.error(error);
          res.status(500).json({ error: 'Internal Server Error' });
        }
      }

    });

    // Login Endpoint
    app.post('/login', async (req, res) => {
      const { email, password } = req.body;

      if (!email) {
        return res.status(400).json({ error: 'Missing Email plase provide Email' });
      }else if (!password) {
        return res.status(400).json({ error: 'Missing Password plase provide Password' });
      }
    
      // Find user by email
      const user = await User.findOne({ email });
    
      if (!user) {
        return res.status(401).json({ error: 'Invalid email' });
      }
    
      // Compare hashed password
      const passwordMatch = await bcrypt.compare(password, user.password);
    
      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid password' });
      }

      const expiresIn = 86400;
    
      // Update lastLogin
      user.lastLogin = new Date();
      await user.save();

      const lastLoginFormatted = user.lastLogin.toLocaleString();
    
      // Generate JWT token
      const token = jwt.sign({ email: user.email, firstName: user.firstName, lastName: user.lastName }, 'secret_key');
    
      res.json({ 
        message: 'Login successful',
        token,
        expiresIn,
        lastLogin: lastLoginFormatted, });
    });