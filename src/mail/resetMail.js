const nodemailer = require('nodemailer');

const sendResetEmail = async (email, resetUrl) => {
    try {
        // Brevo SMTP configuration
        const transporter = nodemailer.createTransport({
          host: 'smtp-relay.brevo.com', // Brevo SMTP server
          port: 587, // Port for TLS
          secure: false, // true for 465 (SSL), false for other ports
          auth: {
            user: '850fee001@smtp-brevo.com', // Your Brevo SMTP login process.env.EMAIL_USER,
            pass: 'nUzmwcTGpCSv60O7', // Replace with your Brevo SMTP password process.env.EMAIL_PASS,
          },
        });

        const mailOptions = {
            from: 'KnowledgeSun <dubeyshivam1911@gmail.com>', // Sender address
            to: email,
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
            Please click on the following link, or paste this into your browser to complete the process:\n\n
            ${resetUrl}\n\n
            If you did not request this, please ignore this email and your password will remain unchanged.\n`,
        };

        await transporter.sendMail(mailOptions);
        console.log('Password reset email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
};

module.exports = { sendResetEmail };