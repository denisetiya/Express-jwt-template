import express, { Request, Response } from "express";
import router from "./router";
import { authenticateJWT } from "./middleware/jwt.auth";
import response from "./utils/response.api";
import limiter from "./middleware/rate.limiter";


const app = express();

// app.use(blockIPMiddleware);

app.use(limiter);

app.use(express.json());

app.use("/v1/",authenticateJWT, router);



app.use((req: Request, res: Response) => {
    response(res, 404, "Not Found", "are you developer or hacker ?");
})

app.listen(3000, () => {
    console.log("Server started on port 3000");
});