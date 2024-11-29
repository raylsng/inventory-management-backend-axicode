const express = require("express");

const { createMaterial, getAllMaterial, getMaterialById, editMaterialById, deleteMaterialById } = require("./material.service");

const router = express.Router();
const authorizeJWT = require("../middleware/authorizeJWT");
const whAuthorization = require("../middleware/whAuthorization");

// WH Only create material
router.post("/", whAuthorization, async (req, res) => {
    try {
        const newMaterialData = req.body;
        const newMaterial = await createMaterial(newMaterialData);
        res.status(201).json(newMaterial);
    } catch (error) {
        res.status(400).send(error.message)  
    }   
});

// All Role  get All Material 
router.get("/", authorizeJWT, async (req, res) => {
    try {
        const material = await getAllMaterial()
        res.status(200).send(material);
    } catch (error) {
        res.status(500).send(error.message);    
    }  
});

// All Role  get All Material get material by Id
router.get("/:id", authorizeJWT, async (req, res) => {
    try {
        const materialId = parseInt(req.params.id);
        const material = await getMaterialById(materialId);
        res.status(200).send(material)
    } catch (error) {
        res.status(400).send(error.message);  
    }   
});

// Role WH  Update  Material
router.put("/:id", whAuthorization, async (req, res) => {
    try {
        const materialId = req.params.id;
        const materialData = req.body;
        const updatematerial = await editMaterialById(materialId,materialData);
        res.send(updatematerial)
    } catch (error) {
        res.status(400).send(error.message)   
    }    
});

// Role WH Delete Material
router.delete("/:id", whAuthorization, async (req,res) => {
    try {
        const materialId = req.params.id
        await deleteMaterialById(materialId)
        res.status(204).json({message: "item deleted"})
    } catch (error) {
        res.status(400).send(error.message);    
    } 
});

module.exports = router;