const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 5000;
const SECRET_KEY = "your_secret_key"; // Cambia esto por una clave segura en producción

app.use(cors());
app.use(bodyParser.json());

// Simulación de una base de datos de usuarios
const users = [];

// Ruta de registro (Signup)
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.json({ message: "Usuario registrado exitosamente" });
});

// Ruta de inicio de sesión (Login)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(user => user.username === username);
    if (!user) return res.status(400).json({ message: "Usuario no encontrado" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ message: "Contraseña incorrecta" });

    // Genera un token JWT
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
});

// Ruta protegida (requiere autenticación)
app.get('/protected', (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: "Acceso denegado" });

    try {
        const verified = jwt.verify(token, SECRET_KEY);
        res.json({ message: "Acceso a la ruta protegida", user: verified });
    } catch (err) {
        res.status(401).json({ message: "Token no válido" });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});

