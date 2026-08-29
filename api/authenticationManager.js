const express = require('express');
const router = express.Router();

const AuthenticatedUser = require('../models/authenticatedUser');
const error = require('../enums/errorCodes.cjs.js');

const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');
const JWT_TOKEN_DURATION = 1 * (24 * 60 * 60); //1 day

const LOG_MODE = 1; //0: NONE; 1: MINIMAL; 2: MEDIUM; 3: HIGH

const API_V = process.env.API_VERSION;

function isAdmin(user){
    return user.administrator || user.superAdministrator;
}
function isSuperAdmin(user){
    return user.superAdministrator;
}

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
        if (!isAdmin(req.loggedUser))
            return res.status(401).json({ error: error("UNAUTHORIZED") });
        if (LOG_MODE >= 1) console.log("Get all authenticated users request!")
        const { administrator, banned, email } = req.query;
        let query = {};
        if (email !== '') query.email = { $regex: email};
        if (banned !== '') query.banned = banned;
        if (administrator !== '') query.administrator = administrator;

        let userList = await AuthenticatedUser.find(query);
            userList = userList.map((user) => {
            return {
                self: API_V + '/authenticatedUsers/' + user._id,
                email: user.email,
                banned: user.banned,
                administrator: isAdmin(user),
                superAdministrator: user.superAdministrator,
                lastLogin: user.lastLogin
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
        if (!user) return res.status(400).json({ error: error("AUTHENTICATED_USER_DELETED") })
        user = {
            self: API_V + '/authenticatedUsers/' + user._id,
            email: user.email,
            banned: user.banned,
            administrator: isAdmin(user),
            superAdministrator: isSuperAdmin(user),
            lastLogin: user.lastLogin
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
router.put("/", async (req, res) => {
    if (LOG_MODE >= 1) console.log("Ban/Unban and Promote/Demote authenticated user request!")
    if (isAdmin(req.loggedUser)){
        let idList = req.body.users;
        if (idList){
            const superAdmin = isSuperAdmin(req.loggedUser);
            for (const id of idList){
                try{
                    authenticatedUser = superAdmin ? await AuthenticatedUser.findOne({superAdministrator: false, _id: id}) : 
                        await AuthenticatedUser.findOne({superAdministrator: false, administrator: false, _id: id});
                }catch(err){
                    return res.status(400).json({ error: error("ID_NOT_FOUND") })
                }
                if (!authenticatedUser) continue;
                if(req.body.banned !== undefined)
                    authenticatedUser.banned = req.body.banned;
                if(req.body.administrator !== undefined)
                    authenticatedUser.administrator = req.body.administrator;
                try{
                    await authenticatedUser.save();
                }catch(err){
                    return res.status(500).json({ error: { message: err } });
                }
            }
            res.status(204).send();
        }else
		    return res.status(401).json({ error: error("WRONG_DATA") })
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});

router.put("/:id", async (req, res) => {
    if (LOG_MODE >= 1) console.log("Ban/Unban and Promote/Demote multiple authenticated user request!")
    if (isAdmin(req.loggedUser)){
        let authenticatedUser;
        try{
            const superAdmin = isSuperAdmin(req.loggedUser);
            authenticatedUser = superAdmin ? await AuthenticatedUser.find({superAdministrator: false, _id: req.params.id}) : 
                await AuthenticatedUser.find({superAdministrator: false, administrator: false, _id: req.params.id});
        }catch(err){
            return res.status(400).json({ error: error("ID_NOT_FOUND") })
        }
        if (!authenticatedUser) res.status(400).json({ error: error("ID_NOT_FOUND") });
        if(req.body.banned)
            authenticatedUser.banned = req.body.banned;
        if(req.body.administrator)
            authenticatedUser.administrator = req.body.administrator;
        try{
            await authenticatedUser.save();
        }catch(err){
            return res.status(500).json({ error: { message: err } });
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

    bcrypt.compare(req.body.password, authenticatedUser.passwordHash, async function(err, result) {
        if (result == true){
            let options = { expiresIn: JWT_TOKEN_DURATION }
            const superAdministrator = authenticatedUser.superAdministrator;
            let payload = {id: authenticatedUser._id, email: authenticatedUser.email, 
                administrator: authenticatedUser.administrator || superAdministrator, 
                superAdministrator, expiresIn: options.expiresIn}
            authenticatedUser.lastLogin = new Date();
            try{
                await authenticatedUser.save();
            }catch(err){
                return res.status(500).json({ error: { message: err } });
            }
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
    const ownAccount = req.loggedUser.id == req.params.id;
    if (ownAccount || isSuperAdmin(req.loggedUser)){
        if (ownAccount) await AuthenticatedUser.deleteOne({_id: req.params.id})
        else await AuthenticatedUser.deleteOne({superAdministrator: false, administrator: false, _id: req.params.id})

        if (LOG_MODE >= 2) console.log("Authenticated user deleted!")
        res.status(204).send();
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});

router.delete('/', async (req, res) => {
    if (LOG_MODE >= 1) console.log("Delete multiple authenticated user request!")
    if (isSuperAdmin(req.loggedUser)){
        let idList = req.body.users;
        console.log(idList);
        if (idList){
            for (const id of idList){
                try{
                    await AuthenticatedUser.deleteOne({superAdministrator: false, _id: id});
                }catch(err){
                    return res.status(400).json({ error: error("ID_NOT_FOUND") })
                }
            }

            if (LOG_MODE >= 2) console.log("Authenticated users deleted!")
            res.status(204).send();
        }else
		    return res.status(401).json({ error: error("WRONG_DATA") })
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});

module.exports = router;