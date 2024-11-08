import express, { Request, Response } from "express";
import url from "./url";
import { authenticateJWT } from "./middleware/jwt.middleware";
import response from "./utils/response.api";
import rateLimit from "express-rate-limit";

const app = express();
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 10, 
    message: 'Too many requests from this IP, please try again later.',
});

app.use(limiter);

app.use(express.json());

app.use("/v1/",authenticateJWT, url);



app.use((req: Request, res: Response) => {
    response(res, 404, "Not Found", "are you developer or hacker ?");
})

app.listen(3000, () => {
    console.log("Server started on port 3000");
});