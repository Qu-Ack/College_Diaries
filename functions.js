const User = require('./Schemas/User')
const asyncHandler = require('express-async-handler')
const {body , validationResult} = require('express-validator');


exports.sign_up =  [
    body("name").trim().escape().isLength({min:3}).withMessage("Name is too short should be atleast 3 characters long"),
    body("email").trim().escape().custom(userEmail=> {
        return new Promise((resolve, reject) => {
            User.findOne({ email: userEmail})
            .then(emailExist => {
                if(emailExist !== null){
                    reject(new Error('Email already exists.'))
                }else{
                    resolve(true)
                }
            })
            
        })
    }).withMessage("Email already exists"),
    body("password").isLength({min:5}),
    body("confirmpassword").custom((value , {req}) => {
        return value === req.body.password
    }).withMessage("confirm password doesn't match with password"),

    asyncHandler(async function(req,res,next) {
        const errors = validationResult(req);

        const user = new User({
            name: req.body.name,
            email:req.body.email,
            password: req.body.password,
            master:req.body.master,
        })

        if (errors.isEmpty()) {
            await user.save();
            res.status(200).json({
                status:"sucesss"
            })
        } else {
            res.json({
                user:user,
                errors:errors,
            })
        }
    })
]