const mongoose = require('mongoose');

const  Schema = mongoose.Schema;

const BlogSchema = new Schema({
    heading: {type: String, required:true},
    text: {
        type:String, required:true
    },
    author: {
        type:String, required:true
    },
    date: {
        type:Date, default: Date.now()
    }
})


module.exports = mongoose.model("blog", BlogSchema);