const express = require('express');
const router = express.Router();

const AuthenticatedUser = require('../models/authenticatedUser');
const error = require('../enums/errorCodes.cjs.js');

const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');
const JWT_TOKEN_DURATION = 1 * (24 * 60 * 60); //1 day

const LOG_MODE = 1; //0: NONE; 1: MINIMAL; 2: MEDIUM; 3: HIGH

const API_V = process.env.API_VERSION;

/**
 * RELATIVE PATH)
 *  .../authenticatedUsers/
 * DESCRIPTION)
 *  the method permits a requesting user to view his own information
 *  or, if administator, view the information of all users and permits
 *  applying filters on the search explained below
 * PARAMS)
 *  query.type: discriminates the type of request the user wants to make
 *              either getting "all" or "personal" user information
 * 
 *  the following query parameters can be left empty '' and will be ignored
 * 
 *  query.email: the email you want to apply a filter on for the search 
 *  query.banned: whether you want to search for accounts banned or not banned
 *  query.administrator: whether you want to search for admin or not admin accounts
 *  query.lastReportDate: the last report date you want to apply a filter on for the search 
 *  query.points:  the totalized account's points you want to apply a filter on for the search 
 * SUCCESSFUL RETURNS)
 *  userList: the list of users' information matching the searched criteria
 */
router.get("/", async (req, res, next) => {
    if(req.query.type == "all"){
        if (req.loggedUser.administrator != true)
            return res.status(401).json({ error: error("UNAUTHORIZED") });
        if (LOG_MODE >= 1) console.log("Get all authenticated users request!")
        const {administrator, banned, email, lastReportDate, points} = req.query;
        let query = {};
        query.email = { $regex: email};

        if (banned !== '') query.banned = banned;
        if (administrator !== '') query.administrator = administrator;
        if (lastReportDate !== '') query.lastReportDate = lastReportDate;
        if (points !== '') query.points = Number(points);

        let userList = await AuthenticatedUser.find(query);
            userList = userList.map((user) => {
            return {
                self: API_V + '/authenticatedUsers/' + user._id,
                email: user.email,
                banned: user.banned,
                administrator: user.administrator
            };
        });
        res.status(200).json(userList);
    }else //req.query.type != "all"
        next()
});

/**
 * DESCRIPTION)
 *  the method permits a requesting user to view his own information
 * SUCCESSFUL RETURNS)
 *  user: the information of the user carrying the request
 */
router.get("/", async (req, res) => {
    if(req.query.type == "personal"){
        if (LOG_MODE >= 1) console.log("Get user request!")
        let user = await AuthenticatedUser.findOne({_id:req.loggedUser.id});
        user = {
            self: API_V + '/authenticatedUsers/' + user._id,
            email: user.email,
            banned: user.banned,
            administrator: user.administrator
        }
        res.status(200).json(user);
    }else //req.query.type != "personal"
        return res.status(400).json({ error: error("MISSING_QUERY_PARAMETER")} )
});

/**
 * RELATIVE PATH)
 *  .../authenticatedUsers/USER_IDENTIFIER
 * DESCRIPTION)
 *  the method permits a requesting user, if administrator, to edit
 *  the ban status or admin priviledges of another user.
 *  The request doesn't work if done for 'System' users
 *  (i.e. admin@gmail.com is the only System user)
 * PARAMS)
 *  id: identifier of the user whose account you want to manage
 *  body.editBan: whether the ban status of a user should be flipped (true<=>false)
 *  body.editAdmin: whether the admin status of a user should be flipped (true<=>false)
 * SUCCESSFUL RETURNS)
 *  authenticatedUser: the edited user
 */
router.put("/:id", async (req, res) => {
    if (LOG_MODE >= 1) console.log("Ban/Unban and Promote/Demote authenticated user request!")
    if (req.loggedUser.administrator == true){
        let authenticatedUser;
        try{
            authenticatedUser = await AuthenticatedUser.findOne({_id: req.params.id});
        }catch(err){
            return res.status(400).json({ error: error("ID_NOT_FOUND") })
        }
        if(req.body.editBan)
            authenticatedUser.banned = !authenticatedUser.banned;
        if(req.body.editAdmin)
            authenticatedUser.administrator = !authenticatedUser.administrator;
        try{
            authenticatedUser.save();
        }catch(err){
            return res.status(500).json({ errorMessage: err });
        }

        res.status(200).json(authenticatedUser);
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});

/**
 * RELATIVE PATH)
 *  .../authenticatedUsers/
 * DESCRIPTION)
 *  the method permits an anonymous requesting user to execute a login
 *  request by passing email and password
 * PARAMS)
 *  body.email: the email of the account trying to log into
 *  body.password: the password of the account trying to log into
 * SUCCESSFUL RETURNS)
 *  authToken: the token that will from now on be used from the client to authenticate requests
 */
router.post("/",  async (req, res) => {
    if (LOG_MODE >= 1) console.log("Authentication request!")
    let authenticatedUser;
    try {
        authenticatedUser = await AuthenticatedUser.findOne({ email: req.body.email.toLowerCase()});
    }catch {
        return res.status(400).json({ error: error("WRONG_DATA") })
    }
    if(!authenticatedUser)
        return res.status(400).json({ error: error("AUTHENTICATED_USER_EMAIL_NOT_FOUND") })
    if(authenticatedUser.banned)
        return res.status(400).json({ error: error("AUTHENTICATED_USER_BANNED") })

    bcrypt.compare(req.body.password, authenticatedUser.passwordHash, function(err, result) {
        if (result == true){
            let options = { expiresIn: JWT_TOKEN_DURATION }
            let payload = {id: authenticatedUser._id, email: authenticatedUser.email, 
                administrator: authenticatedUser.administrator, expiresIn: options.expiresIn}
            res.status(200).json({ authToken: jwt.sign(payload, process.env.JWT_SECRET, options) });
        }
        else
            res.status(400).json({ error: error("WRONG_PASSWORD") })
    });
});

/**
 * RELATIVE PATH)
 *  .../authenticatedUsers/USER_IDENTIFIER
 * DESCRIPTION)
 *  the method permits a requesting user, if administrator, to delete
 *  an existing user by using the identifier of his user account.
 *  The request doesn't work if done for 'System' users
 * PARAMS)
 *  id: identifier of the user whose account you want to delete
 */
router.delete('/:id', async (req, res) => {
        if (LOG_MODE >= 1) console.log("Delete authenticated user request!")
    if (req.loggedUser.administrator == true || req.loggedUser.id == req.params.id ){
        await AuthenticatedUser.deleteOne({_id: req.params.id})
        if (LOG_MODE >= 2) console.log("Authenticated user deleted!")
        res.status(204).send();
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});


module.exports = router;