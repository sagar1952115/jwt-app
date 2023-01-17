const nodemailer = require("nodemailer");
const pug = require("pug");
const htmlToText = require("html-to-text");

module.exports = class Email {
  constructor(user, url, generatedOTP) {
    this.to = user.email;
    this.firstName = user.name.split(" ")[0];
    this.url = url;
    this.from = `test User1 <${process.env.EMAIL_FROM}>`;
    this.generatedOTP = generatedOTP;
  }

  newTransport() {
      return nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
          user: process.env.EMAIL_USERNAME,
          pass: process.env.EMAIL_PASSWORD
      }}) ;
  }

  async send(template, subject) {
    // 1:Render HTML based on a pug template
    const html = pug.renderFile(`${__dirname}/../viewsEmail/${template}.pug`, {
      firstName: this.firstName,
      url: this.url,
      generatedOTP: this.generatedOTP,
      subject,
    });
    // 2: Define email options
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
      text: htmlToText.fromString(html),
    };

    // 3: Create transport and send emails.
    await this.newTransport().sendMail(mailOptions);
  }

  async sendWelcome() {
    await this.send("welcome", "Welcome to the Overpay Family!");
  }

  async sendPasswordReset() {
    await this.send(
      "passwordReset",
      "Your password reset token(valid for only 10 minutes)"
    );
  }
};
