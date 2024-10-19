import express from "express";
import Datastore from "nedb-promises";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import * as config from "./config.js";
import { authenticator } from "otplib";
import qrcode from "qrcode";
import crypto from "crypto";
import NodeCache from "node-cache";

const app = express();
const port = 3000;

// Middleware
app.use(express.json());

const cache = new NodeCache();

// Create a database instance
const usersDB = Datastore.create('Users.db');
const userRefreshTokensDB = Datastore.create('UserRefreshTokens.db');
const userInvalidTokensDB = Datastore.create('UserInvalidTokens.db');   // once the user has logout the access token goes to the 'black list'

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
        const {name, email, password, role} = req.body;
        if(!name || !email || !password){
            return res.status(422).json({message: "Please fill in all fields."});
        }

        // Check for existens of the user
        if(await usersDB.findOne({email: email})){
            return res.status(409).json({message: "User with the same email already exists!"});
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        const newUser = await usersDB.insert({
            name: name,
            email: email,
            password: hashedPassword,
            role: role ? role : 'member',
            'twoFaEnable': false,
            'twoFaSecret': null
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
        const user = await usersDB.findOne({email: email});
        if (!user) {
            return res.status(401).json({message: "User with such email does not exist!"});
        }

        // Check password
        const checkPassword = await bcrypt.compare(password, user.password);
        if(!checkPassword){
            return res.status(401).json({message: "Incorrect password!"});
        }

        //Check if the 2fa is enabled
        if(user.twoFaEnable){
            const tempToken = crypto.randomUUID();

            cache.set(
                config.cacheTemporaryTokenPrefix + tempToken, 
                user._id, 
                config.cacheTemporaryTokenExpiresInSeconds
            );
            
            return res.status(200).json({ 
                tempToken, 
                expiresInSeconds: config.cacheTemporaryTokenExpiresInSeconds
            });
        
        } else {    // the 2fa is Not enabled

            // Create Access Token
            const accessToken = jwt.sign(
                {userId: user._id},
                config.accessTokenSecret,
                {subject: 'accessApi', expiresIn: config.accessTokenExpiresIn}
            );

            // Create Refresh Token
            const refreshToken = jwt.sign(
                {userId: user._id},
                config.refreshTokenSecret,
                {subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn}
            );

            // Save the refresh token in the database
            await userRefreshTokensDB.insert({
                refreshToken: refreshToken,
                userId: user._id
            });

            return res.status(200).json({
                id: user._id,
                name: user.name,
                email: user.email,
                accessToken: accessToken,
                refreshToken: refreshToken
            });
        }
    } catch (error) {
        res.status(500).json({message: error.message});        
    }   
    
});

app.post('/api/auth/login/2fa', async (req, res) => {
    try {
        const { tempToken, totp } = req.body;

        if(!tempToken || !topt)
            return res.status(422).json({ message: 'Please fill out all fields: tempToken and totp.' });

        const userId = cache.get(config.cacheTemporaryTokenPrefix + tempToken);

        if(!userId)
            return res.status(401).json({ messasge: 'The provided temporarily token is incorrect or expired.' });

        const user = await usersDB.findOne({ _id: userId });

        const verify = authenticator.check(totp, user.twoFaSecret);

        if(!verify)
            return res.status(401).json({ message: 'The provided TOTP is incorrect or expired!' });

        // Create Access Token
        const accessToken = jwt.sign(
            {userId: user._id},
            config.accessTokenSecret,
            {subject: 'accessApi', expiresIn: config.accessTokenExpiresIn}
        );

        // Create Refresh Token
        const refreshToken = jwt.sign(
            {userId: user._id},
            config.refreshTokenSecret,
            {subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn}
        );

        // Save the refresh token in the database
        await userRefreshTokensDB.insert({
            refreshToken: refreshToken,
            userId: user._id
        });

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken: accessToken,
            refreshToken: refreshToken
        });

    } catch (error) {
        res.status(500).json({message: error.message});  
    }
})

/**
 * 'POST' 
 * Refresh Token
*/
app.post('/api/auth/refresh-token', async(req, res) => {
    try {
        const {refreshToken} = req.body;

        if(!refreshToken){
            return res.status(401).json({message: 'Refresh token not found.'});
        }
        // Decode and verify the token
        const decodedRefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret);

        // Search the token in the database
        const UserRefreshToken = await userRefreshTokensDB.findOne({refreshToken: refreshToken, userId: decodedRefreshToken.userId});

        // Check if the token was found in the database
        if(!UserRefreshToken) {
            return res.status(401).json({message: 'Refresh token not in the db.'});
        }

        // Remove the token from the database
        await userRefreshTokensDB.remove({_id: UserRefreshToken._id});
        userRefreshTokensDB.compactDatafile();

        // Create new Access and Refresh tokens
        const accessToken = jwt.sign(
            {userId: decodedRefreshToken.userId},
            config.accessTokenSecret,
            {subject: 'accessApi', expiresIn: config.accessTokenExpiresIn}
        );

        const newRefreshToken = jwt.sign(
            {userId: decodedRefreshToken.userId},
            config.refreshTokenSecret,
            {subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn}
        );

        // Save the refresh token in the database
        await userRefreshTokensDB.insert({
            refreshToken: newRefreshToken,
            userId: decodedRefreshToken.userId
        });

        return res.status(200).json({
            accessToken: accessToken,
            refreshToken: newRefreshToken
        });
    } catch (error) {
        if(error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError){
            return res.status(401).json({message: 'Refresh token invalid.'});
        } else {
            res.status(500).json({message: error.message});
        }
    }
});

/**
 * 'GET'
 * two-factor authentication
 */
app.get('/api/auth/2fa/generate', ensureAuthenticated, async(req, res) => {
    try {
        // Get the user details
        const user = await usersDB.findOne({_id: req.user.id});

        const secret = authenticator.generateSecret();
        const uri = authenticator.keyuri(user.email, "auth_project", secret);

        await usersDB.update({_id: req.user.id}, {$set: { 'twoFaSecret': secret }});
        await usersDB.compactDatafile();

        const qrCode = await qrcode.toBuffer(uri, {type: 'image/png', margin: 1});

        res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png');
        return res.status(200).type('image/png').send(qrCode);

    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

app.post('/api/auth/2fa/validate', ensureAuthenticated, async(req, res) => {
    try {
        // Get the TOTP code generated by the Authenticator app
        const { totp } = req.body;

        if(!totp){
            return res.status(422).json({ message: 'TOTP missing.' });
        }

        const user = await usersDB.findOne({ _id: req.user.id });

        // Verify if the user's secret matches the current TOTP generated by the app
        const verify = authenticator.check(totp, user.twoFaSecret);

        if(!verify)
            return res.status(400).json({ message: 'TOTP incorrect or expired.' });

        await usersDB.update({ _id: req.user.id}, { $set: { twoFaEnable: true } });
        await usersDB.compactDatafile();

        return res.status(200).json({ message: 'TOTP validated successfully.' });

    } catch (error) {
        return res.status(500).json({message: error.message});
    }
});

/**
 * 'GET'
 * User Logout
*/
app.get('/api/auth/logout', ensureAuthenticated, async (req, res) => {
    try {
        // remove all refresh tokens related to the userId
        await userRefreshTokensDB.removeMany({userId: req.user.id});
        userRefreshTokensDB.compactDatafile();

        // insert the access token into the 'black' list
        await userInvalidTokensDB.insert({
            accessToken: req.accessToken.value,
            userId: req.user.id,
            expirationTime: req.accessToken.exp
        });

        return res.status(204).send();
    } catch (error) {
        res.status(500).json({message: error.message}); 
    }
});

/**
 * 'GET'
 * Current User
*/
app.get('/api/users/current/', ensureAuthenticated, async(req, res) => {
    try {
        // Search for the user in the database
        const user = await usersDB.findOne({_id: req.user.id}); // look at the middleware function for req.user = ...

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email
        });
    } catch (error) {
        res.status(500).json({message: error.message});   
    }
});

/**
 * 'GET'
 * Admin
*/
app.get('/api/users/admin/', ensureAuthenticated, authorize(['admin']), async (req, res) => {
    return res.status(200).json({message: "Only admins can access this route!"});
    
});

/**
 * 'GET'
 * Moderator
*/
app.get('/api/users/moderator/', ensureAuthenticated, authorize(['admin', 'moderator']), async (req, res) => {
    return res.status(200).json({message: "Only admins and moderators can access this route!"});
    
});


// Middleware
async function ensureAuthenticated(req, res, next){
    const accessToken = req.headers.authorization;

    if(!accessToken)
        return res.status(401).json({message: "Access token not found."});

    // Check if the user had logged out
    if(await userInvalidTokensDB.findOne({accessToken: accessToken})){
        return res.status(401).json({message: 'User logged out.'});
    }

    try {
        // if the verification fails, throws an error and goes to the catch
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);

        req.accessToken = {value: accessToken, exp: decodedAccessToken.exp}; // creates req.accessToken
        req.user = {id: decodedAccessToken.userId};                          // creates req.user

        next();

    } catch (error) {
        if(error instanceof jwt.TokenExpiredError){
            return res.status(401).json({message: 'Access token expired.'});
        } else if(error instanceof jwt.JsonWebTokenError){
            return res.status(401).json({message: 'Access token invalid.'});
        } else {
            return res.status(500).json({message: error.message});
        }
    }    
}

function authorize(roles = []) {
    return async function (req, res, next) {
        const user = await usersDB.findOne({_id : req.user.id});

        if(!user || !roles.includes(user.role)){
            return res.status(403).json({message: "Accesss denied."});
        }

        next();
    }
}


app.listen(port, () => {
    console.log(`Server running on port: ${port}`);
});