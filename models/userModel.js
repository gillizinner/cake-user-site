const mongoose = require("mongoose");
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const {config} = require("../config/secret");

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    //, ורק דייט הוא אובייקט כי לא רצינורק לתת לו טיפוס תאריך אלא גם ערך ברירת מחדל בנוסף כל רשומה תקבל את התאריך של עכשיו
    dateCreated: {
        type: Date, default: Date.now()
    }
});

exports.UserModel = mongoose.model("users", userSchema);

exports.createToken = (user_id) => {
    let token = jwt.sign({ _id: user_id }, config.tokenSecret, { expiresIn: "60mins" });
    return token;
}

exports.validateUser = (_reqBody) => {
    let joiSchema = Joi.object({
        name: Joi.string().min(2).max(50).required(),
        email: Joi.string().min(2).max(100).email().required(),
        password: Joi.string().min(6).max(50).required(),
    })

    return joiSchema.validate(_reqBody);
}
exports.loginValid = (_reqBody) => {
    let joiSchema = Joi.object({
        email: Joi.string().min(2).max(100).email().required(),
        password: Joi.string().min(6).max(50).required(),
    })

    return joiSchema.validate(_reqBody);
}