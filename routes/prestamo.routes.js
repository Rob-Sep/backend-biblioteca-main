const express = require('express');
const router = express.Router();

const prestamoController = require('../controllers/prestamo.controller');

router.get('/', prestamoController.getPrestamos);

router.post('/', prestamoController.createPrestamo);

router.put('/:id', prestamoController.updatePrestamo);

router.post('/devolver/:id', prestamoController.archivarPrestamo);

router.delete('/eliminar/:id', prestamoController.eliminarPrestamoCorrecion);

router.get('/historial', prestamoController.getHistorial);

module.exports = router;