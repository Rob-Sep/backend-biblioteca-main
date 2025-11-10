const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const usuarioSchema = new mongoose.Schema({
  nombre: {
    type: String,
    required: [true, 'El nombre es obligatorio']
  },
  correo: {
    type: String,
    required: [true, 'El correo es obligatorio']
  },
  rut: {
    type: String,
    required: [true, 'El rut es obligatorio']
  },
  cargo: {
    type: String,
    enum: ['Estudiante', 'Docente', 'Bibliotecario'],
    default: 'Estudiante'
  },
  rol: {
    type: String,
    enum: ['Admin', 'Usuario'],
    default: 'Admin'
  },
  password: {
    type: String,
    required: true
  },
  situacion: {
    type: String,
    enum: ['Vigente','Atrasado','Bloqueado','Prestamo Activo'],
    default: 'Vigente'
  }
}, 
{
  timestamps: true 
});

usuarioSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

module.exports = Usuario;