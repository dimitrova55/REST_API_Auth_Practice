import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

import * as db from "../config/db.js";
import * as config from "../config/config.js";


/**
 * 'POST'
 * Register
*/
export const register = async (req, res) => {
    try {
        const {name, email, password, role} = req.body;
        if(!name || !email || !password){
            return res.status(422).json({message: "Please fill in all fields."});
        }

        // Check for existens of the user
        if(await db.usersDB.findOne({email: email})){
            return res.status(409).json({message: "User with the same email already exists!"});
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        const newUser = await db.usersDB.insert({
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
}


/**
 * 'POST'
 * Loggin
*/
export const login = async (req, res) => {
    try {
        const {email, password} = req.body;

        // Check for empty field
        if(!email || !password){
            return res.status(422).json({message: "All fields are required!"});
        }

        // Check for validity of the user
        const user = await db.usersDB.findOne({email: email});
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

            db.cache.set(
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
            await db.userRefreshTokensDB.insert({
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
}


/**
 * 'POST' 
 * Refresh Token
*/
export const refresh_token = async(req, res) => {
    try {
        const {refreshToken} = req.body;

        if(!refreshToken){
            return res.status(401).json({message: 'Refresh token not found.'});
        }
        // Decode and verify the token
        const decodedRefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret);

        // Search the token in the database
        const UserRefreshToken = await db.userRefreshTokensDB.findOne({refreshToken: refreshToken, userId: decodedRefreshToken.userId});

        // Check if the token was found in the database
        if(!UserRefreshToken) {
            return res.status(401).json({message: 'Refresh token not in the db.'});
        }

        // Remove the token from the database
        await db.userRefreshTokensDB.remove({_id: UserRefreshToken._id});
        db.userRefreshTokensDB.compactDatafile();

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
        await db.userRefreshTokensDB.insert({
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
}


/**
 * 'GET'
 * User Logout
*/
export const logout = async (req, res) => {
    try {
        // remove all refresh tokens related to the userId
        await db.userRefreshTokensDB.removeMany({userId: req.user.id});
        db.userRefreshTokensDB.compactDatafile();

        // insert the access token into the 'black' list
        await db.userInvalidTokensDB.insert({
            accessToken: req.accessToken.value,
            userId: req.user.id,
            expirationTime: req.accessToken.exp
        });

        return res.status(204).send();
    } catch (error) {
        res.status(500).json({message: error.message}); 
    }
}