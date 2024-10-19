import express from "express";
import * as auth from "../middleware/auth.js";
import * as users from "../controllers/usersControllers.js"

const router = express.Router();


router.get('/current', auth.ensureAuthenticated, users.current);

router.get('/admin', auth.ensureAuthenticated, auth.authorize(['admin']), users.admin);

router.get('/moderator', auth.ensureAuthenticated, auth.authorize(['admin', 'moderator']), users.moderator);

export default router;