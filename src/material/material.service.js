const { insertMaterial, findMaterials, findMaterialsById, editMaterial, deleteMaterial } = require("./material.repository");

async function createMaterial(newMaterialData) {
    const newMaterial = await insertMaterial(newMaterialData)
    return newMaterial;   
}

async function getAllMaterial() {
    const material = await findMaterials()
    return material;  
}

async function getMaterialById(id) {
    const material = await findMaterialsById(id)
    if (!material) {
        throw new Error("material not found"); 
    }
    return material  
}

async function editMaterialById(id,materialData) {
    await getMaterialById(id);
    const updatematerial = await editMaterial(id, materialData)
    return updatematerial   
}

async function deleteMaterialById(id) {
    await getMaterialById(id);
    await deleteMaterial(id);
    
}

module.exports = {
    createMaterial,
    getAllMaterial,
    getMaterialById,
    editMaterialById,
    deleteMaterialById
}