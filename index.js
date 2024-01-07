const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const cookieParser = require("cookie-parser")

const User = require("./UserSchema")


// Connecting to MongoDB
mongoose.connect('mongodb://localhost:27017/local')
    .then(() => {
        console.log('Mongoose Connected successfully');
    })
    .catch((error) => {
        console.error('Error connecting to MongoDB:', error);
    });


const app = express();

app.use(cors({
    origin: "http://localhost:5173",
    credentials: true
}))

require('dotenv').config()
const port = process.env.PORT

app.use(express.json())
app.use(cookieParser())

app.use((err, req, res, next) => {
    console.log(err);
    res.json(err);
    next();
});

// Destructuring functions from the 'jsonwebtoken' module
const { sign, verify } = require('jsonwebtoken')

// Function to create a JWT token for a user
const createToken = (user) => {

    const accessToken = sign(
        {
            username: user.username, id: user.id
        },
        process.env.ACCESSTOKEN)

    return accessToken
}


// Middleware to validate JWT token
const validateToken = (req, res, next) => {
    const accessToken = req.cookies['access-token']
    if (!accessToken) return res.json("user not authenticated")
    try {
        const validToken = verify(accessToken, process.env.ACCESSTOKEN)
        if (validToken) {
            req.authenticated = true
            return next()
        }
    } catch (err) {
        res.json(err)
    }
}
// Route to handle user registration
app.post("/register", async (req, res) => {
    const { username, password } = req.body
    await bcrypt.hash(password, 10).then((hash) => {
        User.create({
            username: username,
            password: hash
        })
    }).then(() => {
        res.json("User Registered")
    }).catch((err) => {
        res.json(err)
    })
})

// Route to handle user login
app.post("/login", async (req, res, next) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username: { $regex: new RegExp(username, "i") } });

        if (!user) {
            res.status(401).json({ success: false, message: "Invalid username or password" });
            return;
        }

        const dbpassword = user.password;

        await bcrypt.compare(password, dbpassword).then((match) => {
            if (!match) {
                res.status(401).json({ success: false, message: "Invalid username or password" });
            } else {
                const accessToken = createToken(user);

                // Set the token as a cookie named "access-token"
                res.cookie("access-token", accessToken, { maxAge: 60 * 60 * 24 * 365 * 1000 });

                // Send the token as part of the response
                res.json({ success: true, accessToken });
            }
        });
    } catch (error) {
        next(error);
    }
});

// Route to handle user logout
app.post("/logout", validateToken, (req, res) => {
    res.clearCookie("access-token");
    res.json({ success: true, message: "User logged out successfully" });
});


app.listen(port, (err) => {
    if (err) {
        console.error("Error starting the server:", err);
    } else {
        console.log("Server has started on port " + port);
    }
});