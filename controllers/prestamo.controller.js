const Prestamo = require('../models/prestamo.model');
const Usuario = require('../models/usuario.model');
const Libro = require('../models/libro.model');
const Historico = require('../models/historico.model');

exports.getPrestamos = async (req, res) => {
  try {
    const prestamos = await Prestamo.find()
      .populate('usuario')
      .populate('libro');
    res.json(prestamos);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener los prestamos', error: error.message });
  }
};

exports.createPrestamo = async (req, res) => {
  try {
    const { usuario: usuarioId, libro: libroId } = req.body;

    const usuario = await Usuario.findById(usuarioId);
    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    if (usuario.situacion !== 'Vigente') { 
      return res.status(403).json({ 
        message: `El usuario ${usuario.nombre} tiene un estado de "${usuario.situacion}" y no puede pedir préstamos.`
      });
    }
    
    const libro = await Libro.findById(libroId);
    if (!libro) {
      return res.status(404).json({ message: 'Libro no encontrado' });
    }
    if (libro.cantidad === 0) {
      return res.status(400).json({ 
        message: `No quedan copias disponibles de "${libro.titulo}"` 
      });
    }

    const nuevoPrestamo = new Prestamo(req.body);
    await nuevoPrestamo.save();

    usuario.situacion = 'Prestamo Activo'; 
    await usuario.save();
    libro.cantidad -= 1; 
    await libro.save();

    const prestamoPopulado = await Prestamo.findById(nuevoPrestamo._id)
      .populate('usuario')
      .populate('libro');

    res.status(201).json(prestamoPopulado);

  } catch (error) {
    res.status(400).json({ message: 'Error al crear el prestamo', error: error.message });
  }
};

exports.archivarPrestamo = async (req, res) => {
  try {
    const { observaciones } = req.body;
    const prestamo = await Prestamo.findById(req.params.id);
    if (!prestamo) {
      return res.status(404).json({ message: 'Prestamo no encontrado' });
    }

    let estadoFinal = 'A tiempo';
    const hoy = new Date();
    hoy.setHours(0, 0, 0, 0);

    if (prestamo.fechaDevolucion && hoy > prestamo.fechaDevolucion) {
      estadoFinal = 'Atrasado';
    }

    const nuevoHistorico = new Historico({
      usuario: prestamo.usuario,
      libro: prestamo.libro,
      fechaPrestamo: prestamo.fechaPrestamo,
      fechaDevolucionEstimada: prestamo.fechaDevolucion,
      fechaDevolucionReal: new Date(),
      estadoEntrega: estadoFinal,
      observaciones: observaciones || 'Sin observaciones'
    });
    await nuevoHistorico.save();

    await Prestamo.findByIdAndDelete(req.params.id);

    await Libro.findByIdAndUpdate(prestamo.libro, { $inc: { cantidad: 1 } });
    
    const otrosPrestamos = await Prestamo.countDocuments({ usuario: prestamo.usuario });
    if (otrosPrestamos === 0) {
      const usuario = await Usuario.findById(prestamo.usuario);
      if (usuario && (usuario.situacion === 'Prestamo Activo')) {
         await Usuario.findByIdAndUpdate(prestamo.usuario, { situacion: 'Vigente' });
      }
    }
    
    res.json({ message: 'Préstamo archivado y libro re-abastecido' });

  } catch (error) {
    res.status(500).json({ message: 'Error al archivar el prestamo', error: error.message });
  }
};

exports.eliminarPrestamoCorrecion = async (req, res) => {
  try {
    const prestamo = await Prestamo.findById(req.params.id);
    if (!prestamo) {
      return res.status(404).json({ message: 'Prestamo no encontrado' });
    }

    await Libro.findByIdAndUpdate(prestamo.libro, { $inc: { cantidad: 1 } });

    await Prestamo.findByIdAndDelete(req.params.id);

    const otrosPrestamos = await Prestamo.countDocuments({ usuario: prestamo.usuario });
    if (otrosPrestamos === 0) {
      const usuario = await Usuario.findById(prestamo.usuario);
      if (usuario && (usuario.situacion === 'Prestamo Activo')) {
         await Usuario.findByIdAndUpdate(prestamo.usuario, { situacion: 'Vigente' });
      }
    }

    res.json({ message: 'Préstamo erróneo eliminado y libro re-abastecido' });

  } catch (error) {
    res.status(500).json({ message: 'Error al borrar el prestamo', error: error.message });
  }
};

exports.getHistorial = async (req, res) => {
  try {
    const historial = await Historico.find()
      .populate('usuario')
      .populate('libro')
      .sort({ fechaDevolucion: -1 });
      
    res.json(historial);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener el historial', error: error.message });
  }
};

exports.updatePrestamo = async (req, res) => {
  try {
    const prestamoActualizado = await Prestamo.findByIdAndUpdate(
      req.params.id, 
      req.body, 
      { new: true } 
    )
    .populate('usuario')
    .populate('libro');

    if (!prestamoActualizado) {
      return res.status(404).json({ message: 'Prestamo no encontrado' });
    }
    
    res.json(prestamoActualizado);
    
  } catch (error) {
    res.status(400).json({ message: 'Error al actualizar el prestamo', error: error.message });
  }
};