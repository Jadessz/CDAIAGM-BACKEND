require('dotenv').config();
console.log("Loaded GOOGLE_CLIENT_ID:", process.env.GOOGLE_CLIENT_ID);
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OAuth2Client } = require('google-auth-library');

const app = express();

// CORS middleware to allow requests from your frontend
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://cdaiagm.netlify.app');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.set('trust proxy', 1);

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true, // must be true for HTTPS
    sameSite: 'none' // must be 'none' for cross-site cookies
  }
}));

process.env.NODE_ENV !== 'production' && require('debug')('passport:strategy');

// Passport setup
require('dotenv').config();

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
},
function(accessToken, refreshToken, profile, done) {
  return done(null, profile);
}));

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

app.use(passport.initialize());
app.use(passport.session());

// Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // Successful authentication, redirect to frontend
    res.redirect('https://cdaiagm.netlify.app/index.html');
  }
);

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json(req.user);
});

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('https://cdaiagm.netlify.app/index.html');
  });
});

const oAuthClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID || '27603356466-9l5343h63kkqs5dh35pkpo81tgs1as50.apps.googleusercontent.com');

app.use(express.json()); // For parsing JSON bodies

app.post('/auth/google/token', async (req, res) => {
  const { id_token } = req.body;
  if (!id_token) return res.status(400).json({ error: 'Missing id_token' });
  try {
    const ticket = await oAuthClient.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID || '27603356466-9l5343h63kkqs5dh35pkpo81tgs1as50.apps.googleusercontent.com',
    });
    const payload = ticket.getPayload();
    // Create a session for the user
    req.login(payload, (err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      res.json({ success: true, user: payload });
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid ID token' });
  }
});

app.listen(3000, () => console.log('Server started on https://cdaiagm.netlify.app'));