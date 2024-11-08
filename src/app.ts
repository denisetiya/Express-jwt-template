import express, { Request, Response } from "express";
import url from "./url";
import { authenticateJWT } from "./middleware/jwt.middleware";
import response from "./utils/response.api";


const app = express();
app.use(express.json());

app.use("/v1/",authenticateJWT, url);

app.use((req: Request, res: Response) => {
    response(res, 404, "Not Found", "are you developer or hacker ?");
})

app.listen(3000, () => {
    console.log("Server started on port 3000");
});