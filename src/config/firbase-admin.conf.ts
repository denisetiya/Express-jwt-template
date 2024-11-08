// import * as admin from 'firebase-admin';

// const serviceAccount = require('./privkey.json');

// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount),
// });

// export default admin;


import * as admin from 'firebase-admin';
import dotenv from 'dotenv';
dotenv.config();

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  }),
});

export default admin;
