const mongoose = require('mongoose');

const Schema = mongoose.Schema;


const UserSchema = new Schema({
    master: {type:String, default:"false"},
    name: {type: String, required:true, min: [3, "Name is Too Short, should be atleast 3 characters long"]},
    email: {type: String, required:true, min: [5, "User name should be atleast 5 characters long"]},
    password: {type:String, required:true},
})
module.exports = mongoose.model("User", UserSchema);