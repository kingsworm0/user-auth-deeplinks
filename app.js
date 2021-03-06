let  express = require('express'),
    exphbs = require('express-handlebars'),
    logger = require('morgan'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    methodOverride = require('method-override'),
    session = require('express-session'),
    passport = require('passport'),
    LocalStrategy = require('passport-local'),
//     TwitterStrategy = require('passport-twitter'),
//     GoogleStrategy = require('passport-google'),
//     FacebookStrategy = require('passport-facebook');
//     Auth starategy


var app = express();

// Configure Express
app.use(logger('combined'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(methodOverride('X-HTTP-Method-Override'));
app.use(session({secret: 'supernova', saveUninitialized: true, resave: true}));
app.use(passport.initialize());
app.use(passport.session());

// Session-persisted message middleware
app.use(function(req, res, next){
  var err = req.session.error,
      msg = req.session.notice,
      success = req.session.success;

  delete req.session.error;
  delete req.session.success;
  delete req.session.notice;

  if (err) res.locals.error = err;
  if (msg) res.locals.notice = msg;
  if (success) res.locals.success = success;

  next();
});

var hbs = exphbs.create({
    defaultLayout: 'main',
app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');

//===============ROUTES===============


var port = process.env.PORT || 5000; //select your port or let it pull from your .env file
app.listen(port);
console.log("listening on " + port + "!");
