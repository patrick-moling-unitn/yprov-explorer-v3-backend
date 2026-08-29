const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require("crypto");
const mailProvider = require('./mailProvider')

const RegisteringUser = require('../models/registeringUser');
const AuthenticatedUser = require('../models/authenticatedUser');
const error = require('../enums/errorCodes.cjs.js');

const router = express.Router();

const EMAIL_CODE_EXPIRATION_TIME_MIN = 15;
const VERIFICATION_CODE_LENGTH = 6; //1 chance of guessing it out of 200.000 with 5 attempts
const MAX_VERIFICATION_ATTEMPTS = 5;

const MIN_USER_PASSWORD_LENGTH = 8;
const SALT_ROUNDS = Number(process.env.HASHING_SALT_ROUNDS);

const LOG_MODE = 1; //0: NONE; 1: MINIMAL; 2: MEDIUM; 3: HIGH

const API_V = process.env.API_VERSION;

function isAdmin(user){
    return user.administrator || user.superAdministrator;
}

/**
 * RELATIVE PATH)
 *  .../registratingUsers/
 * DESCRIPTION)
 *  the method permits a requesting user, if administrator, 
 *  to get all registering users
 * SUCCESSFUL RETURNS)
 *  usersList: the list of all registrating users
 */
router.get("/", async (req, res) => {
    if (isAdmin(req.loggedUser)){
        if (LOG_MODE >= 1) console.log("Registering users get request!")
            
        let usersList; 
        
        if (req.query.type == "invalid") 
            usersList = await RegisteringUser.find({ "verificationCode.expireDate": { $lt: new Date() } });
        else if (req.query.type == "all") 
            usersList = await RegisteringUser.find({});
        else
            return res.status(400).json({ error: error("MISSING_QUERY_PARAMETERS") });

        usersList = usersList.map((user) => {
            return {
                self: API_V + '/registeringUsers/' + user._id,
                email: user.email,
                expireDate: user.verificationCode.expireDate
            };
        });
        res.status(200).json(usersList);
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});

/**
 * RELATIVE PATH)
 *  .../registratingUsers/
 * DESCRIPTION)
 *  the method permits an anonymous requesting user to start
 *  the registration process of a new account
 * PARAMS)
 *  body.email: the email which you want to register the account with
 *  body.password: the password you want to associate with the account
 * SUCCESSFUL RETURNS)
 *  id: the identifier of the registering user used by the client for the confirmation
 */
router.post("/",  async (req, res) => {
    if(req.body.email && req.body.password){ 
        registeringUser = await RegisteringUser.findOne({ email: req.body.email.toLowerCase()});
        let verificationCode = registeringUser ? registeringUser.verificationCode : null;
        if (verificationCode){ //IF USER IS ALREADY VERIFYING
            if (verificationCode.expireDate<new Date()){ //IF THE VERIFICATION CODE EXPIRED DELETE THE USER
                await RegisteringUser.deleteOne(registeringUser);
                registeringUser = null;
            }else{  //IF THE VERIFICATION CODE IS VALID CHECK THE PASSWORD AND RETURN HIS USER ID
                bcrypt.compare(req.body.password, registeringUser.passwordHash, function (err, result) {
                    if (result == true){
                        const secret = verificationCode.secret, expireDate = verificationCode.expireDate, length = verificationCode.code.length;
                        res.status(200).json({ id: registeringUser._id, verificationCode: { secret, expireDate, length }});
                    }
                    else
                        res.status(400).json({ error: error("WRONG_PASSWORD") });
                });
                return; //return dentro bcrypt.compare non impedisce al metodo di coninuare!
            }
        }
        let email = req.body.email.toLowerCase()
        if(email.search("@")==-1 || email.search(".")==-1)
            return res.status(400).json({ error: error("EMAIL_CHOSEN_NOT_VALID") });
        if(registeringUser)
            return res.status(400).json({ error: error("REGISTRATING_USER_DUPLICATED_REQUEST") });
        alreadyExistingEmail = await AuthenticatedUser.findOne({ email: req.body.email.toLowerCase()});
        if(alreadyExistingEmail)
            return res.status(400).json({ error: error("EMAIL_ALREADY_REGISTERED") });
        if (req.body.password.length < MIN_USER_PASSWORD_LENGTH)
            return res.status(400).json({ error: error("REGISTRATING_USER_INVALID_PASSWORD"), minPasswordLength: MIN_USER_PASSWORD_LENGTH });

        let code = "";
        for (let i=0; i<VERIFICATION_CODE_LENGTH; i++)
            code += crypto.randomInt(0, 10);

        const secret = crypto.randomBytes(4).toString("hex"),
              expireDate = new Date(Date.now() + EMAIL_CODE_EXPIRATION_TIME_MIN * 60 * 1000);

        let reguser = new RegisteringUser({
            email: req.body.email,
            passwordHash: await bcrypt.hash(req.body.password, SALT_ROUNDS),
            verificationCode: {
                code,
                secret,
                expireDate
            }
        });

        let mailOptions = {
            subject: '[Explorer] Verify your email',
            text: 'Your verification code is '+ reguser.verificationCode.code + '\n' +
                  'The verification code will expire in '+EMAIL_CODE_EXPIRATION_TIME_MIN+' minutes.'
        };
        mailProvider.sendMail(req.body.email, mailOptions.subject, mailOptions.text);
        try{
            await reguser.save();
            const length = VERIFICATION_CODE_LENGTH;
            res.location(API_V + '/registeringUsers/' + reguser._id).status(201).json(
                {id: reguser._id, verificationCode: { secret, expireDate, length }});
        }catch(err){
            return res.status(500).json({ error: { message: err } });
        }
    }else
        return res.status(400).json({ error: error("MISSING_QUERY_PARAMETERS") });
});

/**
 * RELATIVE PATH)
 *  .../registratingUsers/REG_USER_IDENTIFIER/code
 * DESCRIPTION)
 *  the method permits an anonymous requesting user, having a user identifier, to complete
 *  the registration request of his account by confirming the code sent to his personal email
 * PARAMS)
 *  id: the user identifier of the account you want to confirm the registration
 *  body.code: the code that was sent to your email adress
 * NOTES)
 *  the method proceeds executing below if previous checks are successful
 */
router.post("/:id/code",  async (req, res, next) => {
    const verifyinguser = await RegisteringUser.findById(req.params.id);
    if(!verifyinguser)
        return res.status(400).json({ error: error("INVALID_REGISTRATION_REQUEST") });
    if(verifyinguser.verificationCode.expireDate<new Date()){
        await RegisteringUser.deleteOne({ _id: req.params.id });
        return res.status(400).json({ error: error("REGISTRATION_CODE_EXPIRED") });
    }
    if(verifyinguser.verificationCode.code != req.body.code){
        verifyinguser.verificationCode.attempts++; 
        if (verifyinguser.verificationCode.attempts >= MAX_VERIFICATION_ATTEMPTS){
            await RegisteringUser.deleteOne({ _id: req.params.id });
            return res.status(400).json({ error: error("REGISTRATION_CODE_MAX_ATTEMPTS_REACHED") });
        }else{
            try{
                await verifyinguser.save();
            }catch(err){
                return res.status(500).json({ error: { message: err } });
            }
        }
        const remainingAttempts = MAX_VERIFICATION_ATTEMPTS - verifyinguser.verificationCode.attempts;
        return res.status(400).json({ error: error("REGISTRATION_CODE_INVALID"), remainingAttempts });
    }
    req['registeringUser'] = verifyinguser;
    next(); //CONTINUES BELOW<!!!>
});

/**
 * DESCRIPTION)
 *  the method converts the registering user into a new authenticated user since
 *  it has verified the code above. The temporary registrating user will be deleted.
 * NOTES)
 *  the method shares the parameters of the one above
 */
router.post("/:id/code",  async (req, res) => {
    const newuser = req['registeringUser'];
	let user = new AuthenticatedUser({
        email: newuser.email,
        lastLogin: new Date(),
        passwordHash: newuser.passwordHash
    });
    await RegisteringUser.deleteOne({_id: req.params.id});
    try{
        await user.save();
        if (LOG_MODE >= 1) console.log('Registering user created!');
        let mailOptions = {
            subject: '[Explorer] Welcome aboard',
            text: 'Your registration was successful' + '\n' +
                  'You can now login and enjoy the full functionalities of the Explorer!'
        };
        mailProvider.sendMail(newuser.email, mailOptions.subject, mailOptions.text);
        return res.location(API_V + '/authenticatedUsers/' + user._id).status(201).json({ success: true });
    }catch(err){
        return res.status(500).json({ error: { message: err } });
    }
});

/**
 * RELATIVE PATH)
 *  .../registratingUsers/REG_USER_IDENTIFIER
 * DESCRIPTION)
 *  the method permits a requesting user, if administrator, to
 *  delete a user who's carrying a registration process
 * PARAMS)
 *  id: the user identifier of the account you want to delete
 */
router.delete('/:id', async (req, res, next) => {
    if (isAdmin(req.loggedUser)){
        await RegisteringUser.deleteOne({ _id: req.params.id });
        if (LOG_MODE >= 1) console.log('Registering user removed!');
        res.status(204).send();
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});

router.delete('/:id/secret', async (req, res) => {
    if (req.body.secret){
        await RegisteringUser.deleteOne({ "verificationCode.secret": req.body.secret, _id: req.params.id });
        if (LOG_MODE >= 1) console.log('Registering user removed!');
        res.status(204).send();
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});

/**
 * RELATIVE PATH)
 *  .../registratingUsers/
 * DESCRIPTION)
 *  the method permits a requesting user, if administrator, to
 *  delete all users carrying a registration process
 */
router.delete('/', async (req, res) => {
    if (isAdmin(req.loggedUser)){
        if (LOG_MODE >= 1) console.log('Registering users delete request!');
        if (req.query.type == "invalid")
            await RegisteringUser.deleteMany({ "verificationCode.expireDate": { $lt: new Date() } });
        else if (req.query.type == "all")
            await RegisteringUser.deleteMany();
        else 
            return res.status(400).json({ error: error("MISSING_QUERY_PARAMETERS") });
            
        res.status(204).send();
    }else
		return res.status(401).json({ error: error("UNAUTHORIZED") })
});

module.exports = router;