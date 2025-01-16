import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

const sendEmail = async (
  to: string, 
  subject: string, 
  token: string,
  email : string
) => {

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.APP_EMAIL, 
      pass: process.env.APP_PASS,   
    },
  });


  const mailOptions = {
    from: 'api@helsense.com', 
    to,                          
    subject,                                     
    html: (``)                  
  };

  try {
    const info = await transporter.sendMail(mailOptions);
  
    return info.response
    
  } catch (error) {
    console.error('Error sending email:', error);
    throw error; 
  }
};

export default sendEmail;