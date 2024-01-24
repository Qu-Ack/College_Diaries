const express = require('express');
require('dotenv').config()
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser')
const functions  = require('./functions');

main().catch((err) => {console.log(err)})
async function main() {
    await mongoose.connect(process.env.DB_STRING);
}


const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended:true}))
app.use(cookieParser());


app.get('/', (req,res,next) => {
    res.send("Hello from the api")
})
app.post('/api/signup', functions.sign_up);
app.post('/api/login' ,  functions.login);
app.post('/api/blog' ,functions.verifyToken, functions.createBlog)
app.get('/api/blog', functions.getBlogs);
// app.post('/api/comment', functions.verifyToken, functions.postComments);
// app.get('/api/comment', functions.verifyToken, functions.getCommments)
app.get('/api/blog/:id' ,functions.getBlog, functions.getCommments)
app.post('/api/blog/:id' , functions.postComments);

// ERROR HANDLING


app.use((error,req,res,next) => {
    console.log(`error ${error.message}`)
    next(error)
})

app.use(function(error, req,res,next){
    res.header("Content-Type", 'application/json');
    const status = error.status || 500;

    res.status(status).send(error.message)
})

app.use((request,response, next) => {
    response.status(404)
    response.send("Invalid Path")
})


app.listen(process.env.PORT || 3000, '0.0.0.0',  () => {console.log("server on ....")});

