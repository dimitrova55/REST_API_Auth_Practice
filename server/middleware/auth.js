import express from "express";
import jwt from "jsonwebtoken";


import * as db from "../config/db.js";
import * as config from "../config/config.js";


export async function ensureAuthenticated(req, res, next){
    const accessToken = req.headers.authorization;

    if(!accessToken)
        return res.status(401).json({message: "Access token not found."});

    // Check if the user had logged out
    if(await db.userInvalidTokensDB.findOne({accessToken: accessToken})){
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

export function authorize(roles = []) {
    return async function (req, res, next) {
        const user = await db.usersDB.findOne({_id : req.user.id});

        if(!user || !roles.includes(user.role)){
            return res.status(403).json({message: "Accesss denied."});
        }

        next();
    }
}
