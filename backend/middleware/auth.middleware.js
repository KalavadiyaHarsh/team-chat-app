import jwt from "jsonwebtoken";
import userModel from "../models/user.model.js";

export const authUser = async (req, res, next) => {
    try {
        const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).send({ error: "Unauthorized User" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);

        if (!user || !user.isTokenValid(decoded.iat)) {
            return res.status(401).json({ error: "Session expired, please log in again" });
        }

        req.user = user;
        next();
    } catch (error) {
        console.log(error);
        res.status(401).send({ error: "Unauthorized User" });
    }
};
