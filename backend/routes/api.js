var express = require('express');
var router = express.Router();
var userModel = require("../models/useModel");
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
const secret = "secret";

// SIGN UP
router.post("/signUp", async (req, res) => {
  let { username, name, email, phone, password } = req.body;

  let emailCon = await userModel.findOne({ email: email });
  let phoneCon = await userModel.findOne({ phone: phone });

  if (emailCon) return res.json({ success: false, message: "Email already exists" });
  if (phoneCon) return res.json({ success: false, message: "Phone already exists" });

  bcrypt.genSalt(10, function (err, salt) {
    bcrypt.hash(password, salt, async function (err, hash) {
      let user = await userModel.create({
        username,
        name,
        email,
        phone,
        password: hash
      });
      res.json({ success: true, message: "User created successfully", userId: user._id });
    });
  });
});

// LOGIN
router.post("/login", async (req, res) => {
  let { email, password } = req.body;
  let user = await userModel.findOne({ email });

  if (!user) return res.json({ success: false, message: "Invalid email" });

  bcrypt.compare(password, user.password, function (err, result) {
    if (result) {
      let token = jwt.sign({ email: user.email, userId: user._id }, secret);
      res.json({ success: true, message: "Login successful", userId: user._id, token });
    } else {
      res.json({ success: false, message: "Invalid password" });
    }
  });
});

module.exports = router;
