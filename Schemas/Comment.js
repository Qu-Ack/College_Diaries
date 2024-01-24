const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const CommentSchema = new Schema({
    content: {type: String, required:true},
    user: {type: Schema.Types.ObjectId , ref: "User"},
    blog: {type:Schema.Types.ObjectId, ref:"blog"},
})


module.exports = mongoose.model("comment", CommentSchema);