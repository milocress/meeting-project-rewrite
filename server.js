const commander  = require('commander');
const inquirer = require('inquirer');
const neo4j          = require('neo4j-driver').v1;
const graphenedbURL  = ( process.env.GRAPHENEDB_BOLT_URL )      ?  process.env.GRAPHENEDB_BOLT_URL     : "bolt://localhost:7687";
const graphenedbUser = ( process.env.GRAPHENEDB_BOLT_USER )     ? process.env.GRAPHENEDB_BOLT_USER     : "neo4j";
const graphenedbPass = ( process.env.GRAPHENEDB_BOLT_PASSWORD ) ? process.env.GRAPHENEDB_BOLT_PASSWORD : "those scoreless irate scruffy zombie manhunts" ;

const driver  = neo4j.driver(graphenedbURL, neo4j.auth.basic(graphenedbUser, graphenedbPass))
const session = driver.session();
function findByEmail(email, cb) {
    session.run(
        'MATCH (user:User {email: $email}) RETURN user', { email: email }
    ).then(results => {
        session.close();
        if (!results.records[0]) {
            return cb(null, null);

}
        return cb(null, results.records[0].get('user'));
    });
}

function findById(id, cb) {
    session.run(
        'MATCH (user) WHERE ID(user) = $identity RETURN user', { identity: id }
    ).then(results => {
        session.close();
        if (!results.records[0]) {
            return (null, null)
        }
        return cb(null, results.records[0].get('user'));
    });
}
function userAdd(email, password, role, firstName, lastName, cb) {
    session.run(
        'CREATE (user:User {email: $email, hashed_password: $hashed_password, role: $role, firstName: $firstName, lastName: $lastName}) RETURN user',
        {
            email: email,
            hashed_password: generateHash(password),
            role: role,
            firstName: firstName,
            lastName: lastName
        }
    ).then(results => {
        session.close();
        user = results.records[0].get('user');
        cb(null, user);
    });
}
function userDel(userId, cb) {
    session.run(
        'MATCH (user:User) WHERE ID(user) = $userId DETACH DELETE user',
        {userId: userId}
    ).then(results => {
        session.close();
        cb(null);
    });
}
function getUsers(cb) {
    session.run(
        'MATCH (users:User) RETURN users'
    ).then(results => {
        session.close();
        if (!results.records.length) { return cb(null, []); }
        users = [];
        results.records.forEach(res => {
            users.push(res.get('users'));
        })
        return cb(null, users);
    });
}

function getStudents(cb) {
    session.run(
        'MATCH (users:User) WHERE users.role = "Student" RETURN users'
    ).then(results => {
        session.close();
        if (!results.records.length) { return cb(null, []); }
        users = [];
        results.records.forEach(res => {
            users.push(res.get('users'));
        })
        return cb(null, users);
    });
}
function findActivityById(activityId, cb) {
    session.run(
        'MATCH (activity:Activity) WHERE ID(activity) = $activityId RETURN activity',
        {activityId: activityId}).then(results => {
            session.close();
            ret = results.records[0].get('activity');
            if (!ret) { return cb("Activity Not Found", null); }
            return cb(null, ret);
        });
}

/**
   Arguments:
   - creatorId (int)
   The ID of the user who created the activity
   - activityName (string)
   The name of the activity
   - activityDescription (string)
   A description of the activity
   - requested attendees (int array)
   The emails of all requested attendees
   - cb (function)
   Callback Function
**/
function activityAdd(creatorId, activityName, activityDescription, requestedAttendees, cb) {
    session.run(
        'MATCH (creator:User) WHERE ID(creator) = $creatorId CREATE (creator)-[:CREATED]->(activity:Activity {name: $activityName, description: $activityDescription}) RETURN activity',
        {
            creatorId: creatorId,
            activityName: activityName,
            activityDescription: activityDescription
        }
    ).then(results => {
        session.close();
        activityId = results.records[0].get('activity')["identity"]["low"];
        activityInvite(activityId, requestedAttendees, function(err, activity) {
            return cb(null, activity);
        })
    });
}
function activityDel(activityId, cb) {
    session.run(
        'MATCH (activity:Activity) WHERE ID(activity) = $activityId DETACH DELETE activity',
        {
            activityId: activityId
        }
    ).then(results => {
        session.close();
        return cb(null);
    })
}
function activityInvite(activityId, requestedAttendees, cb) {
    requestedAttendees.forEach(user_email => {
        session.run(
            'MATCH (activity:Activity),(student:User) WHERE ID(activity) = $activityId AND student.email = $email CREATE (student)-[rel:INVITED_TO]->(activity) rel.time = TIMESTAMP() RETURN student',
            {
                activityId: activityId,
                email: user_email
            }
        ).then(results => {
            session.close();
        });
    });
    return cb(null, results.records[0].get('activity'));
}

function joinActivity(userId, activityId, cb) {
    session.run(
        'MATCH (activity:Activity),(student:User) WHERE ID(activity) = $activityId AND ID(student) = $studentId CREATE (student)-[rel:JOINED]->(activity) rel.time = TIMESTAMP() RETURN activity'
    ).then(results => {
        session.close();
        return cb(null, results.records[0].get('activity'));
    });
}

function getActivities(cb) {
    session.run(
        'MATCH (activities:Activity) RETURN activities'
    ).then(results => {
        session.close();
        if (!results.records.length) { return cb(null, []); }
        activities = [];
        results.records.forEach(res => {
            activities.push(res.get('activites'));
        })
        return cb(null, activities);
    });
}

function messageAdd(senderId, recipientId, message, cb) {
    session.run(
        'MATCH (sender:User), (recipient:User) WHERE ID(sender) = $senderId AND ID(recipient) = $recipientId CREATE (sender)-[message:SENT]->(recipient) message.body = $message message.time = TIMESTAMP() RETURN message',
        {
            senderId: senderId,
            recipientId: recipientId,
            message: message
        }
    ).then(results => {
        session.close();
        return cb(null, results.records[0].get('message'))
    });
}
function messageDel(messageId, cb) {
    session.run(
        'MATCH ()-[r:SENT]->() WHERE ID(r) = messageId DELETE r',
        {
            messageId: messageId
        }
    ).then(results => {
        session.close();
        return cb(null);
    });
}

function getMessagesForUser(userId, cb) {
    session.run(
        'MATCH (recipient:User)<-[message:SENT]-(sender:User) WHERE ID(recipient) = $userId RETURN message, sender',
        {
            userId: userId
        }
    ).then(results => {
        session.close();
        var ret = [];
        console.log("I got here");
        if (!results.records.length) { return cb(null, []); }
        results.records.forEach((record) => {
            console.log('Pushing...');
            ret.push({
                sender: record.get('sender'),
                messages: record.get('message')
            });
        });
        return cb(null, ret);
    });
}
const passport = require('passport');
const bcrypt   = require('bcrypt-nodejs');

function generateHash (password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(12), null);
}
function validPassword (password, hashed_password) {
    return bcrypt.compareSync(password, hashed_password);
};
var Strategy = require('passport-local').Strategy;


// Configure the local strategy for use by Passport.
//
// The local strategy require a `verify` function which receives the credentials
// (`username` and `password`) submitted by the user.  The function must verify
// that the password is correct and then invoke `cb` with a user object, which
// will be set at `req.user` in route handlers after authentication.
passport.use('local-login', new Strategy({
    // by default, local strategy uses username and password, we will override with email
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true // allows us to pass back the entire request to the callback
},
    function(req, email, password, cb) {
        findByEmail(email, function(err, user) {
            if (err) { return cb(err); }
            if (!user) { return cb(null, false); }
            if (!validPassword(password, user["properties"]["hashed_password"])) { return cb(null, false); }
            req.user = user;
            return cb(null, user);
        });
    }));

//Local-signup
passport.use('local-signup', new Strategy({
    // by default, local strategy uses username and password, we will override with email
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true // allows us to pass back the entire request to the callback
},
    function(req, email, password, cb) {
        findByEmail(email, function (err, user) {
            if (!user) {
                userAdd(email, password, req.body.role_selector, function(err, new_user) {
                    cb(null, new_user);
                });
            }
            else {
                cb("User Exists", null);
            }
        })
    }));
passport.serializeUser(function(user, cb) {
    cb(null, user["identity"]["low"]);
});

passport.deserializeUser(function(id, cb) {
    findById(id, function (err, user) {
        if (err) { return cb(err); }
        cb(null, user);
    });
});
const express = require('express');
const app = express();
var router = express.Router();
var express_session = require('express-session');

var flash = require('connect-flash');

var morgan       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');

app.set('view engine', 'pug');


app.use(express_session({
    secret: 'undone cape discount magma outnumber repeater',
    resave: true,
    saveUninitialized: true
})); // session secret

app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions

//app.use(morgan('dev')); // log every request to the console
app.use(cookieParser()); // read cookies (needed for auth)
app.use(bodyParser.json()); // get information from html forms
app.use(bodyParser.urlencoded({
    extended: true
})); // get information from html forms
app.use(express.static('public'));

app.get('/', function (req, res) {
    if (req.user) { console.log("Welcome " + req.user["properties"]["firstName"]); }
    res.render('index', {
        title:"CVU Study Form",
        user: req.user
    });
});
//Depending on how the webapp is implemented, we may not want random people creating an account.
//This code is useful, however, so I will use it.
app.get('/signup', function (req, res) {
    res.render('signup', { title: "Sign Up" });
});

app.post('/signup', passport.authenticate('local-signup', {
    successRedirect : '/profile',
    failureRedirect : '/signup',
    failureFlash    : true
}));

app.get('/login', function (req, res) {
    res.render('login', { title: "Log in" });
});

// process the login form
app.post('/login', passport.authenticate('local-login', {
    successRedirect : '/profile', // redirect to the secure profile section
    failureRedirect : '/login', // redirect back to the login page if there is an error
    failureFlash : true // allow flash messages
}));
app.get('/profile', isLoggedIn, function (req, res) {
    const activityPromise = new Promise((resolve, reject) => {
        getActivities((err, activities) => {
            if (err) { reject(err); }
            else { resolve(activities); }
        });
    });
    const messagePromise = new Promise((resolve, reject) => {
        console.log(req.user["identity"]["low"]);
        getMessagesForUser(req.user["identity"]["low"], (err, messages) => {
            if (err) { reject(err); }
            else { resolve(messages); }
        });
    });
    const userPromise = new Promise((resolve, reject) => {
        getUsers((err, users) => {
            if (err) { reject(err); }
            else { resolve(users); }
        });
    });
    Promise.all([activityPromise, messagePromise, userPromise]).then((results) => {
        activities = results[0];
        messages = results[1];
        users = results[2];
        res.render('profile', {
            title: "Profile",
            user: req.user,
            activities: activities,
            messageRecords: messages,
            users: users
        });
    })
});
app.get('/create', isTeacher, function(req, res) {
    res.render('create', { title: "Creating Activity" });
});
app.post('/create', isTeacher, function(req, res) {
    res.redirect('/profile');
});
app.get('*', function(req, res, next){
    res.status(404);

    // respond with html page
    if (req.accepts('html')) {
        res.render('404', { title:"Error 404, Page not found.", url: req.url });
        return;
    }
});
function isLoggedIn(req, res, cb) {

    if (req.isAuthenticated()) {
        return cb();
    }

    res.redirect('/');
}

function isTeacher(req, res, cb) {
    if (req.isAuthenticated() && ( req.user["properties"]["role"] == "Teacher" || req.user["properties"]["role"] == "Admin")) {
        return cb();
    }

    res.redirect('/');
}
const port = (process.env.PORT) ? process.env.PORT : 3000;
app.listen(port);
