//jshint esversion:6
require("dotenv").config()
const express = require("express")
const ejs = require("ejs")
const morgan = require("morgan")
const mongoose = require("mongoose")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.use(morgan('dev'))
app.use(express.static("public"))
app.set('view engine', "ejs")
app.use(express.urlencoded({ extended: true }))

// app.set('trust proxy', 1) // trust first proxy
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    // cookie: { secure: true }
}))
app.use(passport.initialize())
app.use(passport.session())

//mongoose and mongodb
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true })
mongoose.set('useCreateIndex', true)
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
})

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy());
// use static serialize and deserialize of model for passport session support
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

//routes
app.get('/', (req, res) => res.render("home"))
app.get('/login', (req, res) => res.render("login"))
app.get('/register', (req, res) => res.render("register"))

app.get('/secrets', (req, res) => {
    User.find({ "secret": { $ne: null } }, function (err, found) {
        if (err) {
            console.log(err)
        } else {
            if (found) {
                res.render("secrets", { usersWithSecrets: found })
            }
        }
    })
})

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit")
    } else {
        res.redirect("/login")
    }
})

app.post('/submit', (req, res) => {
    const secret = req.body.secret
    //get current user id
    User.findById(req.user.id, function (err, found) {
        if (err) {
            console.log(err)
        } else {
            if (found) {
                found.secret = secret;
                found.save(function () {
                    res.redirect('/secrets')
                })
            }
        }
    })
})

app.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});

app.post('/register', (req, res) => {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err)
            res.redirect("/register")
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    });
})

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, function (err) {
        if (err) { return next(err); }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    });
})

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log('Server listening on ' + PORT))