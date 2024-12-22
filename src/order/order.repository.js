const prisma = require("../db");

// [FIXED, revisi di phAuth] Ngebug gak bisa create order, kemungkinan karena ganti middleware PH dari authorizeJWT.
async function createOrder(userId, materialId, orderQty) {
    try {
        const newOrder = await prisma.order_spk.create({
            data: {
                userId,
                materialId,
                orderQty,
                status: "PENDING"
            }
        });
        return newOrder;
    } catch (error) {
        throw new Error("failed create order"); 
    }
    
}

async function findOrder() {
    try {
        const order = await prisma.order_spk.findMany({
            include:{
                material:{
                    select:{
                        name: true
                    },
                },
                user:{
                    select:{
                        username: true,
                    },
                },
            },
        });
        return order
    } catch (error) {
        throw new Error("failed to fetch order");    
    } 
}

async function findOrderByUserId(userId) {
    try {
        const order = await prisma.order_spk.findMany({
            where: {
                userId: parseInt(userId)
            },
            include: {
                material:{
                    select:{
                        name : true
                    }
                }
            }
        })
        return order
    } catch (error) {
        throw new Error("failed to fetch order by user Id");  
    } 
}

async function findOrderById(id) {
    const order = await prisma.order_spk.findUnique({
        where:{
            id: parseInt(id)
        }
    })
    return order  
}

async function updateOrderStatus(orderId, status) {
    try {
        await prisma.order_spk.update({
            where: {
                id: parseInt(orderId)
            },
            data: {
                status: status  // Update status saja
            }
        });
    } catch (error) {
        console.error("Error details:", error);  // Tambah logging untuk detail error
        throw new Error("Failed to update your status");
    }   
}

module.exports ={
    createOrder,
    findOrder,
    findOrderByUserId,
    findOrderById,
    updateOrderStatus
}