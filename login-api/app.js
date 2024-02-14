var express = require('express')
var cors = require('cors')
var app = express()

var bodyParser = require('body-parser')

const bcrypt = require('bcrypt');
const saltRounds = 10;

var jwt = require('jsonwebtoken')
const secret = 'RegisterLogin3591'

var jsonParser = bodyParser.json()

app.use(cors())

//contecion database
const mysql = require('mysql2');
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'log_reg_system'
})

//register here
app.post('/register', jsonParser, function (req, res, next) {

    
        //hash password here
        bcrypt.hash(req.body.password, saltRounds, function(err, hash) {

            //insert data to database
            connection.execute(
                'INSERT INTO users(email,password,fname,lname) VALUES (?,?,?,?)',
                [req.body.email, hash, req.body.fname, req.body.lname],
                function(err,results,fields){
                    if(err){
                        res.json({status: 'error', message: err});
                        return
                    }
                    res.json({status: 'Ok'})
                }
            );
    });

    //var email = req.body.email;
    
})

//login here
app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE email=?',
        [req.body.email],
        function(err,users,fields){
            //Detect errors
            if(err){
                res.json({status: 'error', message: err});
                return
            }
            //Detect user no info
            if(users.length == 0){
                res.json({status: 'error', message: 'no user found'});
                return
            }
            //Check the code from the database
            bcrypt.compare(req.body.password, users[0].password, function(err, isLogin) {
                //check login success
                if(isLogin){
                    var token = jwt.sign({email: users[0].email}, secret
                        ,
                        //exp token is 2hours
                        {
                            expiresIn: "2h"
                        });
                    res.json({status: 'Ok',message: 'Login success',token})
                    return
                
                } 
                //check login failed
                else{
                    res.json({status: 'error',message: 'Login failed'})
                    return
                }
            });
            
        }
    );

})

app.post('/authen', jsonParser, function (req, res, next) {
    try{
        //requset token headers
        const token = req.headers.authorization.split(' ')[1]
        //verify token with secret
        var decoded = jwt.verify(token, secret);
        res.json({status: 'Ok', decoded})

    }catch(err){
        res.json({status: 'error', message: err.message})
    }
    
})

//server alive
app.listen(3591, function () {
  console.log('CORS-enabled web server listening on port 3591')
})