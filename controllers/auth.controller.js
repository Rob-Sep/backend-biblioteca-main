const Usuario = require('../models/usuario.model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.login = async (req, res) => {
  try {
    const { loginIdentifier, password } = req.body;

    const usuario = await Usuario.findOne({
      $or: [
        { correo: loginIdentifier },
        { nombre: loginIdentifier } 
      ]
    });

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario o correo no encontrado' });
    }

    const isMatch = await bcrypt.compare(password, usuario.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    const payload = {
      id: usuario._id,
      rol: usuario.rol
    };
    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.json({ token });

  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
};

exports.register = async (req, res) => {
  try {
    const { loginIdentifier, password } = req.body;

    // 1. Verificar si el usuario o correo ya existe
    let usuarioExistente = await Usuario.findOne({
      $or: [
        { correo: loginIdentifier },
        { nombre: loginIdentifier }
      ]
    });

    if (usuarioExistente) {
      return res.status(400).json({ message: 'Usuario o correo ya existe' });
    }

    // 2. Hashear la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 3. Crear el nuevo usuario
    // Para esta puerta trasera, usamos el 'loginIdentifier' para ambos campos
    const nuevoUsuario = new Usuario({
      nombre: loginIdentifier,
      correo: loginIdentifier,
      password: hashedPassword
      // El rol se asignará según el 'default' de tu modelo
    });

    // 4. Guardar en la base de datos
    await nuevoUsuario.save();

    // 5. Enviar respuesta de éxito
    // No devolvemos un token, forzamos a que inicie sesión después
    res.status(201).json({ message: 'Usuario registrado con éxito' });

  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
};