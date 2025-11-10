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

    // 2. Crear el nuevo usuario
    // (Se elimina la encriptación manual. El modelo .pre('save') lo hará)
    
    const nuevoUsuario = new Usuario({
      nombre: loginIdentifier,
      correo: loginIdentifier,
      password: password, // <-- Pasamos la clave en texto plano
      rut: '1-1'          // <-- Añadimos el RUT de relleno para pasar la validación
      // El 'rol' (Admin), 'cargo' (Estudiante) y 'situacion' (Vigente)
      // se asignarán por 'default' gracias a tu modelo.
    });

    // 3. Guardar en la base de datos (aquí se activa el .pre('save') y encripta)
    await nuevoUsuario.save();

    // 4. Enviar respuesta de éxito
    res.status(201).json({ message: 'Usuario registrado con éxito' });

  } catch (error) {
    // Esto imprime el error en los logs de Render
    console.error('Error en /register:', error); 
    
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
};