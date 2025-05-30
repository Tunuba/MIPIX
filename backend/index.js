const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS para cualquier origen en desarrollo
app.use(cors());
app.use(express.json());

// MongoDB
mongoose.connect('mongodb://localhost:27017/miapp')
  .then(() => console.log('✅ MongoDB conectado'))
  .catch(err => console.error('❌ Error MongoDB:', err));

// Schema Usuario
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true, 
    trim: true,
    minlength: 3
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    trim: true,
    lowercase: true
  },
  password: { 
    type: String, 
    required: true, 
    minlength: 6
  }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// REGISTRO
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }
    
    if (username.trim().length < 3) {
      return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }
    
    const existingUser = await User.findOne({ 
      $or: [{ username: username.trim() }, { email: email.trim().toLowerCase() }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'Usuario o email ya registrado' });
    }
    
    const passwordHash = await bcrypt.hash(password, 12);
    const user = new User({ 
      username: username.trim(), 
      email: email.trim().toLowerCase(), 
      password: passwordHash 
    });
    
    await user.save();
    
    res.status(201).json({ 
      message: 'Usuario creado exitosamente', 
      user: { 
        id: user._id,
        username: user.username, 
        email: user.email 
      } 
    });
  } catch (error) {
    console.error('Error en registro:', error.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña son obligatorios' });
    }
    
    const user = await User.findOne({ username: username.trim() });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(400).json({ error: 'Credenciales incorrectas' });
    }
    
    res.json({ 
      message: 'Login exitoso', 
      user: { 
        id: user._id,
        username: user.username, 
        email: user.email 
      } 
    });
  } catch (error) {
    console.error('Error en login:', error.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Listar usuarios
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// Test básico
app.get('/api/test', (req, res) => {
  res.json({ message: 'Servidor funcionando' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor en puerto ${PORT}`);
});