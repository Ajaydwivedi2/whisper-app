require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session')
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

main().catch(err => console.log(err));

async function main() {

    const mongoURL = "mongodb+srv://season-admin:" + process.env.MONGOPASS + "@cluster0.5rpqoyu.mongodb.net/userDB";

    // await mongoose.connect('mongodb://127.0.0.1:27017/userDB');
    await mongoose.connect(mongoURL);

    const userSchema = new mongoose.Schema({
        username: String,
        password: String,
        googleId: String,
        facebookId: String,
        provider: { type: String, default: 'Locally_registered' },
        secret: Array

    });


    userSchema.plugin(passportLocalMongoose);
    userSchema.plugin(findOrCreate);

    const User = mongoose.model('User', userSchema);

    passport.use(User.createStrategy());

    passport.serializeUser(function (user, cb) {
        process.nextTick(function () {
            cb(null, { id: user.id, username: user.username });
        });
    });
    passport.deserializeUser(function (user, cb) {
        process.nextTick(function () {
            return cb(null, user);
        });
    });

    // ************Google Authentication ***************************//

    passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
        function (accessToken, refreshToken, profile, cb) {
            User.findOrCreate({ googleId: profile.id, username: profile.displayName, provider: profile.provider }, function (err, user) {
                return cb(err, user);
            });
        }
    ));

    app.get('/auth/google',
        passport.authenticate('google', { scope: ['profile'] }));

    app.get('/auth/google/secrets',
        passport.authenticate('google', { failureRedirect: '/login' }),
        function (req, res) {
            res.redirect("/secrets")
        });

    // Facebook Authentication ***************************//

    passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secret"
    },
        function (accessToken, refreshToken, profile, cb) {
            User.findOrCreate({ facebookId: profile.id, username: profile.displayName, provider: profile.provider }, function (err, user) {
                return cb(err, user);
            });
        }
    ));
    app.get('/auth/facebook',
        passport.authenticate('facebook'));

    app.get('/auth/facebook/secret',
        passport.authenticate('facebook', { failureRedirect: '/login' }),
        function (req, res) {
            // Successful authentication, redirect home.
            res.redirect('/secrets');
        });

    // ********************** Get request **************************//

    app.get('/', function (req, res) {
        res.render('home');
    })

    app.get('/login', function (req, res) {
        res.render('login', { errMsg: "", username: "", password: "" });
    })

    app.get('/register', function (req, res) {
        res.render('register');
    })

    app.get("/secrets", function (req, res) {

        if (req.isAuthenticated()) {
            User.find({ secret: { $ne: null } }).then(function (foundUsers) {
                if (foundUsers) {
                    res.render("secrets", { UsersWithSecrets: foundUsers })
                }
            })
        } else {
            res.redirect("login")
        }

    });

    app.get("/logout", function (req, res) {
        req.logout(function (err) {
            if (err) {
                console.log(err);
            } else {

                res.redirect("/");
            }
        });
    });

    app.get("/submit", function (req, res) {
        if (req.isAuthenticated()) {
            res.render("submit")
        } else {
            res.redirect("/login");
        }
    })

    // ********************** Post request **************************//

    app.post("/submit", function (req, res) {
        const userSecret = req.body.secret;
        User.findById(req.user.id).then(function (foundUser) {
            if (foundUser) {

                foundUser.secret.push(userSecret);
                foundUser.save().then(function (secretSaved) {
                    if (secretSaved) {
                        res.redirect("/secrets")
                    }
                }).catch(function (err) {
                    console.log(err);
                })
            }
        }).catch(function (err) {
            console.log(err);
        })
    });

    app.post('/register', function (req, res) {

        User.findOne({ username: req.body.username }).then(function (foundUser) {
            if (foundUser) {
                res.render('login', { errMsg: "Please login, user already registered", username: req.body.username, password: req.body.password });
            } else {
                User.register({ username: req.body.username }, req.body.password, function (err, user) {
                    if (err) {
                        res.redirect('/register');
                    } else {

                        passport.authenticate('local')(req, res, function () {
                            res.redirect("/secrets");
                        });
                    }
                })
            }
        }).catch(function (err) {
            console.log(err);
        })


    });

    app.post('/login', function (req, res) {

        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.logIn(user, function (err) {
            if (err) {
                console.log(err);
            } else {

                User.findOne({ username: req.body.username }).then(function (foundUser) {
                    if (foundUser) {
                        passport.authenticate("local")(req, res, function () {
                            res.redirect("/secrets");
                        });
                    } else {

                        res.render('login', { errMsg: "Please provide a valid username and password.", username: req.body.username, password: req.body.password });

                    }
                }).catch(function (err) {
                    console.log(err);
                })

            }
        })
    });


    app.listen(3000, function (req, res) {
        console.log("Server is running on port 3000");
    })
}
