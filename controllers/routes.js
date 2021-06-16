const express = require('express');
const router = express.Router();
const user = require('../models/user');
const bcryptjs = require('bcryptjs');
const passport = require('passport');
require('./passportLocal')(passport);
require('./googleAuth')(passport);

function checkAuth(req, res, next){
    if(req.isAuthenticated()){
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
        next();
    }else{
        res.redirect('/')
    }
}
router.get('/', (req, res) => {
    if(req.isAuthenticated()){
        res.render("index", { logged: true });
    }else{
        res.render("index", { logged: false });
    }
});

router.get('/login', (req, res) => {
    res.render("login");
});

router.get('/signup', (req, res) => {
    res.render("signup");
});

router.post('/signup', (req, res) => {
    const { email, username, password, confirmpassword } = req.body;
    if (!email || !username || !password || !confirmpassword ){
        res.render("signup", { err: "All Fields Required!", csrfToken: req.csrfToken() });
    }else if(password != confirmpassword){
        res.render("signup", { err: "Passwords don't match!", csrfToken: req.csrfToken() });
    }else{
        user.findOne({ $or: [{ email: email }, { username: username }]}, (err, data) => {
            if(err) throw err;
            if(data){
                res.render("signup", { err: "User Exists, Try logging in!", csrfToken: req.csrfToken()})
            }else{
                bcryptjs.genSalt(12, (err, salt) => {
                    if (err) throw err;
                    bcryptjs.hash(password, salt, (err, hash) => {
                        if (err) throw err;
                        user({
                            username: username,
                            email: email,
                            password: hash,
                            googleId: null,
                            provider: 'email',
                        }).save((err, data) => {
                            if(err) throw err;
                            res.redirect("/login");
                        })
                    })
                })
            }
        })
    }
});
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        failureRedirect: '/login',
        successRedirect: '/',
        failureFlash: true,
    })(req, res, next);
});
router.get('/logout', (req, res) => {
    req.logout();
    req.session.destroy((err) => {
        res.redirect('/')
    })
});
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email',] }));

router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    res.render('profile', { username: req.user.username })
});
router.get('/profile', checkAuth, (req, res) => {
    res.render('profile', { username: req.user.username })
});

module.exports = router