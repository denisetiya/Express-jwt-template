import rateLimit from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 1 * 1000, // 1 second
  max: 10, // limit each IP to 10 requests per second
  message: "Too many requests from this IP, please try again later.",
});

export default limiter;

