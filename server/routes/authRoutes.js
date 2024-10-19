import express from "express";

import * as auth from "../middleware/auth.js";
import * as authContr from "../controllers/authControllers.js";
import * as mfa from "../controllers/2FA_Controllers.js";

const router = express.Router();


app.post('/register', authContr.register);
app.post('/login', authContr.login);
app.get('/logout', auth.ensureAuthenticated, authContr.logout);
app.post('/refresh-token', authContr.refresh_token);


app.post('/2fa/login', mfa.login);
app.get('/2fa/generate', auth.ensureAuthenticated, mfa.generate);
app.post('/2fa/validate', auth.ensureAuthenticated, mfa.validate);


export default router;