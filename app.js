import express from "express";

import authRoute from "./server/routes/authRoutes.js";
import usersRoute from "./server/routes/usersRoutes.js";

const app = express();
const port = 3000;

// Middleware
app.use(express.json());


// 'GET'
app.get('/', (req, res) => {
    res.send("REST API Authentication and Authorization");
});


// Routes
app.use('/api/auth', authRoute);
app.use('/api/users', usersRoute);


app.listen(port, () => {
    console.log(`Server running on port: ${port}`);
});