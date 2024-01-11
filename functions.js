const User = require('./Schemas/User')
const asyncHandler = require('express-async-handler')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
require('dotenv').config()

exports.sign_up = [
    body("name").trim().escape().isLength({ min: 3 }).withMessage("Name is too short should be atleast 3 characters long"),
    body("email").trim().escape().custom(userEmail => {
        return new Promise((resolve, reject) => {
            User.findOne({ email: userEmail })
                .then(emailExist => {
                    if (emailExist !== null) {
                        reject(new Error('Email already exists.'))
                    } else {
                        resolve(true)
                    }
                })

        })
    }).withMessage("Email already exists"),
    body("password").isLength({ min: 5 }),
    body("confirmpassword").custom((value, { req }) => {
        return value === req.body.password
    }).withMessage("confirm password doesn't match with password"),

    asyncHandler(async function (req, res, next) {
        const errors = validationResult(req);

        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: req.body.password,
            master: req.body.master,
        })

        if (errors.isEmpty()) {
            bcrypt.hash(process.env.SECRET_PWD_HASH, 10, async (err, hash) => {
                if (err) {
                    console.log(err)
                } else {
                    user.password = hash;
                    await user.save();
                    res.status(200).json({
                        status: "success"
                    })
                }
            })
        } else {
            res.json({
                user: user,
                errors: errors,
            })
        }
    })
]


exports.login = [
    body("email").trim().escape().isEmail().withMessage("should be a valid email"),

    asyncHandler(async (req, res, next) => {
        const errors = validationResult(req)

        if (errors.isEmpty()) {
            User.findOne({ email: req.body.email }).then(user => {
                bcrypt.compare(process.env.SECRET_PWD_HASH, user.password).then(match => {
                    if (match) {
                        const token = jwt.sign({email: req.body.email, password: req.body.password}, process.env.TOKEN_SECRET);
                        res.cookie("access_token", token)
                        res.status(200).json({
                            status:"Logged In",
                        })
                    } else {
                        res.status(400).json({
                            status: "Bad password"
                        })
                    }
                }).catch(err => {
                    next(err)
                })
            }).catch(err => {
                next(err)
            })
        } else {
            res.json({
                errors: errors
            })
        }
    })
] 