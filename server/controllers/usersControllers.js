import express from "express";
import * as db from "../config/db.js";

/**
 * 'GET'
 * Current User
*/
export const current = async(req, res) => {
    try {
        // Search for the user in the database
        const user = await db.usersDB.findOne({_id: req.user.id}); // look at the middleware function for req.user = ...

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email
        });
    } catch (error) {
        res.status(500).json({message: error.message});   
    }
}

/**
 * 'GET'
 * Admin
*/
export const admin = async (req, res) => {
    return res.status(200).json({message: "Only admins can access this route!"});
    
}

/**
 * 'GET'
 * Moderator
*/
export const moderator = async (req, res) => {
    return res.status(200).json({message: "Only admins and moderators can access this route!"});
    
}