const express = require('express');
require('dotenv').config()
const mongoose = require('mongoose');
const functions  = require('./functions');

main().catch((err) => {console.log(err)})
async function main() {
    await mongoose.connect(process.env.DB_STRING);
}


const app = express();
app.use(express.json());
app.use(express.urlencoded({extended:true}))

app.post('/api/signup', functions.sign_up);


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


app.listen(process.env.PORT, () => {console.log("server on ....")});

