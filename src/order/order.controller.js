const express = require ("express");
const router = express.Router();
const orderService = require("./order.service");
//const { getMaterialById } = require("../material/material.service");
const authorizeJWT = require("../middleware/authorizeJWT");
const phAuthorization = require("../middleware/phAuthorization");
const whAuthorization = require("../middleware/whAuthorization");
const { getOrderById } = require("./order.service")

// Role PH create Order SPK
router.post("/order", phAuthorization, async (req, res) => {
    try {
        const userId = req.userId;
        const {materialId, orderQty} = req.body
        const newOrder = await orderService.orderMaterial(userId, materialId, orderQty);
        res.status(201).json(newOrder);
    } catch (error) {
        res.status(400).send(error.message);
        
    } 
})

// All Role Get All Order
router.get("/", authorizeJWT, async (req, res) => {
    try {
        const order = await orderService.getAllOrder();
        res.send(order) 
    } catch (error) {
        res.status(500).send(error.message)   
    }  
});

//WH Get Order By PH Id
router.get("/user", whAuthorization, async (req, res) => {
    const userId = req.userId;
    try {
        const order = await orderService.getOrderByUserId(userId);
        res.status(200).send(order)
    } catch (error) {
        res.status(500).send(error.message)  
    }
})

// All Role Get Order By Id
router.get("/:id", authorizeJWT, async (req, res) => {
    try {
        const orderId = req.params.id
        const order = await getOrderById(orderId)
        res.status(200).send(order)
    } catch (error) {
        res.status(400).send(error.message)   
    } 
})

// Role WH Accept Order SPK
router.patch("/verify/:orderId", whAuthorization, async (req, res) => {
    try {
        const { orderId } = req.params;
        const {status} = req.body
        await orderService.verifyOrder(orderId, status)
        res.status(200).json({message : "SPK Request Received Successfully"})
    } catch (error) {
        res.status(400).send(error.message)
    }

})

router.patch("/received/:orderId", phAuthorization, async (req, res) => {
    try {
        const { orderId } = req.params;
        const {status} = req.body
        // await orderService.verifyOrder(orderId, status)
        await orderService.receivedOrder(orderId, status)
        res.status(200).json({message : "SPK Request DONE Successfully"})
    } catch (error) {
        res.status(400).send(error.message)
        
    }

})


/*
// Role PH Received Ordered Material
router.post("/return/:orderId", phAuthorization, async (req, res) => {
    try {
      const { orderId } = req.params;
      //const { userId } = req.body;
      const userId = req.userRole;
      const order = await orderService.getOrderById(orderId);
  
      if (order.userRole !== userId) {
        return res.status(403).json({ message: "Role PH is Unauthorized" });
      }
  
      await orderService.returnItem(orderId);
      res.status(200).json({ message: "Item Delivered" });
    } catch (error) {
      res.status(400).send(error.message);
    }
  });  
*/

module.exports = router;