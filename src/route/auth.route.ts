import { Router } from "express";
import authController from "../controller/auth.controller.js";
import useAuth from "../middleware/auth.middleware.js";

const router = Router();



router.post('/login', authController.login)
router.post('/sign-up', authController.signUp)
router.post('/logout', useAuth, authController.logout)
router.post('/refresh-token', authController.refreshToken)

export default router;