import express from "express";
import Datastore from "nedb-promises";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
const port = 3000;

// Middleware
app.use(express.json());

// Create a database instance
const users = Datastore.create('Users.db');

// 'GET'
app.get('/', (req, res) => {
    res.send("REST API Authentication and Authorization");
});


/**
 * 'POST'
 * Register
*/
app.post('/api/auth/register', async (req, res) => {
    try {
        const {name, email, password} = req.body;
        if(!name || !email || !password){
            return res.status(422).json({message: "Please fill in all fields."});
        }

        // Check for existens of the user
        if(await users.findOne({email: email})){
            return res.status(409).json({message: "User with the same email already exists!"});
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        const newUser = await users.insert({
            name: name,
            email: email,
            password: hashedPassword 
        });
        res.status(201).json({
            message: "User registered!",
            id: newUser._id
        });

    } catch (error) {
        res.status(500).json({message: error.message});        
    }
});


/**
 * 'POST'
 * Loggin
*/
app.post('/api/auth/login', async (req, res) => {
    try {
        const {email, password} = req.body;

        // Check for empty field
        if(!email || !password){
            return res.status(422).json({message: "All fields are required!"});
        }

        // Check for validity of the user
        const user = await users.findOne({email: email});
        if (!user) {
            return res.status(401).json({message: "User with such email does not exist!"});
        }

        // Check password
        const checkPassword = await bcrypt.compare(password, user.password);
        if(!checkPassword){
            return res.status(401).json({message: "Incorrect password!"});
        }

        const accessToken = jwt.sign({userId: user._id}, )

    } catch (error) {
        res.status(500).json({message: error.message});        
    }   
    
});

app.listen(port, () => {
    console.log(`Server running on port: ${port}`);
});