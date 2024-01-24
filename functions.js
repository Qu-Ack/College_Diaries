const User = require('./Schemas/User');
const Comment = require('./Schemas/Comment')
const Blog = require('./Schemas/Blog');
const asyncHandler = require('express-async-handler');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

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
            bcrypt.hash(req.body.password, 10, async (err, hash) => {
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
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(200).json({
                errors: errors,
            });
        }

        const { password } = req.body;
        try {
            const user = await User.findOne({ email: req.body.email });

            if (!user) {
                return res.status(200).json({
                    status: "User not found"
                });
            }
            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.status(200).json({
                    status: "Bad password"
                });
            }
            const token = jwt.sign({ email: req.body.email, password: user.password, master: user.master, symbol: user._id, name: user.name }, process.env.TOKEN_SECRET);
            res.cookie("access-token", token);
            res.status(200).json({
                token,
                status: "Logged In"
            })
        } catch (err) {
            console.error(err);
            next(err);
        }
    })
];



exports.verifyToken = async function (req, res, next) {
    // res.header("Access-Control-Allow-Origin", "*");
    const authHeader = req.headers.authorization;
    if (typeof authHeader != 'undefined') {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
            if (err) {
                next();
            }

            req.user = user;
            next();
        });
    } else {
        res.status(401).json({
            status: "No Login Token provided"
        })
    }
}



exports.createBlog = [
    body('heading').trim().escape(),
    body('text'),
    body('author').trim().escape(),



    asyncHandler(async function (req, res, next) {
        const errors = validationResult(req);

        const blog = new Blog({
            heading: req.body.heading,
            text: req.body.text,
            author: req.body.author,
        })


        if (!errors.isEmpty()) {
            res.status(200).json({
                errors: errors.array(),
                blog,
            })
        } else {
            if (typeof req.user == undefined) {
                res.status(401).json({
                    status: "Master is not logged in"
                })
            } else {
                if (req.user.master == 'true') {
                    await blog.save();
                    res.status(201).json({
                        status: "Blog created Successfully"
                    })
                } else {
                    res.status(401).json({
                        status: "Master is not logged in"
                    })
                }

            }
        }
    })
]


exports.getBlogs = asyncHandler(async function (req, res, next) {
    const blogs = await Blog.find({}).exec();
    res.status(200).json({
        blogs,
    })
})


exports.getBlog = asyncHandler(async function (req, res, next) {
    const blog = await Blog.findOne({ _id: req.params.id }).exec();
    req.middlewareData = blog;
    next();
})

exports.postComments = [
    body('content').trim().escape().isLength({ min: 2 }),

    asyncHandler(async function (req, res, next) {
        const errors = validationResult(req);

        let comment = new Comment({
            content: req.body.content,
            user: req.body.user,
            blog: req.body.blog,
        })
        if (!errors.isEmpty()) {
            res.status(200).json({
                errors: errors.array(),
                comment: comment
            })
        } else {
            await comment.save();
            res.status(201).json({
                status: "Comment posted succesfully"
            })
        }
    })
]


exports.getCommments = asyncHandler(async function (req, res, next) {
    const authHeader = req.headers.authorization;
    if (typeof authHeader != 'undefined') {
        const token = authHeader.split(' ')[1];

        if (token == 'undefined') {
            res.status(200).json({
                blog: req.middlewareData,
            })
        } else {
            jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
                if (err) {
                    res.status(401).json({
                        status: "Forbidden"
                    })
                }

            });
            const comments = await Comment.find({ blog: req.params.id }).populate('user').exec();
            res.status(200).json({
                status: "success",
                comments,
                blog: req.middlewareData,
            })
        }
    } else {
        res.status(401).json({
            status: "No Login Token provided"
        })
    } 


})