const express = require("express");
const bcrypt = require("bcrypt");
const { UserModel, validateUser, loginValid, createToken } = require("../models/userModel");
const jwt = require("jsonwebtoken");
const { auth } = require("../auth/auth");
const router = express.Router();

router.get("/", async (req, res) => {
    let perPage = Math.min(req.query.perPage, 20) || 4; //המספר המקסימלי יהיה 20 כדי שהאקר לא ינסה להכניס מספר עצום בשאילתה ויצליח להקריס את המערכת
    let page = req.query.page || 1;
    let sort = req.query.sort || "_id";
    let reverse = req.query.reverse == "yes" ? -1 : 1;

    try {
        let data = await UserModel
            .find({}) //returns all the list because ther isnt a filter function sent but an empty object
            .limit(perPage)//defines max items for page, whats the limit
            .skip((page - 1) * perPage)//מגדיר מאיזה מספור של אוביקטים להתחיל להציג, באיזה עמוד לאחוז, שזה בעצם כמה לדלג - מספר העמוד -1 כפול מספר האובייקטים לעמוד, למשל עמוד ראשון זה לדלג 0 אובייקטיםת עמוד שני לדלג עבור מס אוביקטים לעמוד אחד, כי מדלגים רק עמוד וכו
            .sort({ [sort]: reverse })//ממין את הרשימה לפי הפרמטר שנשלח ולפי אם ברוורס או לא
        res.json(data)
    } catch (err) {
        console.log(err);
        res.status(500).json({ msg: "err", err })
    }
})

router.get("/myInfo", auth, async (req, res) => {
    let userInfo = await UserModel.findOne({ _id: req.tokenData._id }, { password: 0 });//dont take password of user
    res.json(userInfo);
})
router.get("/myEmail", auth, async (req, res) => {
    let emailInfo = await UserModel.findOne({ _id: req.tokenData._id }, { email: 1 }); //take only email of this user
    res.json(emailInfo);
})

router.post("/", async (req, res) => {
    let valiBody = validateUser(req.body);
    if (valiBody.error) {
        return res.status(500).json(valiBody.error.details);
    }
    try {
        let user = new UserModel(req.body);
        user.password = await bcrypt.hash(user.password, 10);//מצפינים את הסיסמה בעזרת ביקריפט כך שתישמר ההצפנה בבסיס נתונים, חוזק ההצפנה זה 10
        await user.save();
        user.password = "*****";
        res.status(201).json(user);
    } catch (err) {
        if (err.code == 11000) {//, מגדירים בקומפס איזה תכונה תהיה ייחודית, טעות 11000 זו טעות מובנית בפוסטמן כאשר יש כפילות
            return res.status(400).json({ msg: "Email already in system try login", code: 11000 })
        }
        console.log(err);
        res.status(500).json({ msg: "err", err })
    }
})

router.post("/login", async (req, res) => {
    let valdiateBody = loginValid(req.body);
    if (valdiateBody.error) {
        return res.status(400).json(valdiateBody.error.details)
    }
    try {
        // לבדוק אם המייל שנשלח בכלל יש רשומה של משתמש שלו
        let user = await UserModel.findOne({ email: req.body.email })
        if (!user) {
            // שגיאת אבטחה שנשלחה מצד לקוח
            return res.status(401).json({ msg: "User and password not match 1" })
        }
        // בדיקה הסימא אם מה שנמצא בבאדי מתאים לסיסמא המוצפנת במסד
        let validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(401).json({ msg: "User and password not match 2" })
        }
        let newToken = createToken(user._id);
        res.json({ token: newToken })
        // res.json({ msg: "Success, Need to send to client the token" });
    }
    catch (err) {

        console.log(err)
        res.status(500).json({ msg: "err", err })
    }
})
module.exports = router;