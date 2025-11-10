const express = require('express');
const router = express.Router();

const usuarioController = require('../controllers/usuario.controller');

router.get('/', usuarioController.getUsuarios);

router.post('/', usuarioController.createUsuario);

router.get('/:id', usuarioController.getUsuarioById);

router.put('/:id', usuarioController.updateUsuario);

router.delete('/:id', usuarioController.deleteUsuario);

module.exports = router;