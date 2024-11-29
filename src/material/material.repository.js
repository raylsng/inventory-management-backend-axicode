const prisma = require("../db")

async function insertMaterial(materialData) {
    const newMaterial = await prisma.material.create({
        data: {
            name: materialData.name,
            description: materialData.description,
            stock : materialData.stock
        }
    });
    return newMaterial;   
}

async function findMaterials() {
    const material = await prisma.material.findMany()
    return material   
}

async function findMaterialsById(id) {
    const material = await prisma.material.findUnique({
        where: {
            id: parseInt(id),
        }
    })
    return material
}

async function editMaterial(id, materialData) {
    const updatematerial = await prisma.material.update({
        where: {
            id: parseInt(id)
        },
        data: {
            name : materialData.name,
            description : materialData.description,
            stock : materialData.stock
        }
    })
    return updatematerial

}
async function deleteMaterial(id) {
    await prisma.material.delete({
        where: {
            id: parseInt(id)
        }
    })  
}

async function updatematerial(materialId, newStock) {
    try {
        await prisma.material.update({
            where:{
                id: parseInt(materialId)
            },
            data:{
                stock : newStock
            }
        })
    } catch (error) {
        console.error(error)
    }
    
}

module.exports = {
    insertMaterial,
    findMaterials,
    findMaterialsById,
    editMaterial,
    deleteMaterial,
    updatematerial
}