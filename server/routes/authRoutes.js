import express from "express";

import * as auth from "../middleware/auth.js";
import * as authContr from "../controllers/authControllers.js";
import * as mfa from "../controllers/2FA_Controllers.js";

const router = express.Router();


router.post('/register', authContr.register);
router.post('/login', authContr.login);
router.get('/logout', auth.ensureAuthenticated, authContr.logout);
router.post('/refresh-token', authContr.refresh_token);


router.post('/2fa/login', mfa.login);
router.get('/2fa/generate', auth.ensureAuthenticated, mfa.generate);
router.post('/2fa/validate', auth.ensureAuthenticated, mfa.validate);


export default router;