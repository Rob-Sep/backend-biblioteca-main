const mongoose = require('mongoose');

const prestamoSchema = new mongoose.Schema({
  usuario: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Usuario',
    required: [true, 'El usuario/rut es obligatorio']
  },
  libro: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Libro',
    required: [true, 'El libro es obligatorio']
  },
  fechaPrestamo: {
    type: Date,
    required: [true, 'La fecha de prestamo es obligatoria']

  },
  fechaDevolucion: {
    type: Date,
    required: [true, 'La fecha de prestamo es obligatoria']
  }}, 
{
  timestamps: true 
});

const Prestamo = mongoose.model('Prestamo', prestamoSchema);

module.exports = Prestamo;