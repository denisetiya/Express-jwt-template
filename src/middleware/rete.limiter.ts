import express, { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import response from '../utils/response.api';

const blockedIPs: Set<string> = new Set();

const isBlocked = (ip: string): boolean => blockedIPs.has(ip);

const handler = (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip;
  
    if (typeof ip === 'string') {
      if (isBlocked(ip)) {
        return;
      }
  
      let violationCount = (req.app.get(ip) || 0) + 1;
      req.app.set(ip, violationCount);
  
      if (violationCount >= 5) {
        blockedIPs.add(ip);
        console.log(`IP ${ip} has been blocked because of 5 violations.`);
        return res.status(403).json({
          message: 'IP address is blocked.',
        });
      }
    }
  
    next();
  };
  
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max:15,
  message: 'Too many requests from this IP, please try again later.',
  handler: handler,
});


const blockIPMiddleware = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const ip = req.ip;

    if (!ip) {
        return response(res, 400, "Bad Request", "IP address not found");
    }

    if (isBlocked(ip)) {
        return response(res, 403, "Forbidden", "IP address is blocked");
    }

    next();
};

export {
    limiter,
    blockIPMiddleware
}