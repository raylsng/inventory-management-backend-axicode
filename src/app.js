const express = require('express');
const cors = require('cors')
const app = express();
const dotenv = require('dotenv');
dotenv.config();

const authorizeJWT = require("./middleware/authorizeJWT");
const phAuthorization = require("./middleware/phAuthorization");
const whAuthorization = require("./middleware/whAuthorization");

const APP_PORT = process.env.PORT

app.use(express.json());
app.use(cors());
app.get("/", (req, res) => {
    res.send('Hello kelompok 3!');
});

const authController = require("./auth/auth.controller");
app.use("/api/auth", authController);

const userController = require("./user/user.controller");
app.use("/api/users", phAuthorization, userController);

const materialController = require("./material/material.controller")
app.use("/api/material", materialController);

const orderController = require("./order/order.controller")
app.use("/api/orders", orderController)

app.listen(APP_PORT, () => {
    console.log(`App listening on port ` + APP_PORT);
});

// export default app