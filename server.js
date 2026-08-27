const mongoose = require('mongoose');
const express = require('express')
const cors = require('cors')
require('dotenv').config()

const authenticationManager = require('./api/authenticationManager');
const registrationManager = require('./api/registrationManager');
const requestValidator = require('./api/requestValidator');

const app = express()

app.use(cors())
app.use(express.json())

const API_V = "/api/"+process.env.API_VERSION;
const PORT = process.env.PORT;

app.get(API_V+"/authenticatedUsers", requestValidator) //Devi essere amministratore per ottenere gli utenti
app.delete(API_V+"/authenticatedUsers", requestValidator) //Devi essere amministratore per eliminare gli utenti
app.put(API_V+"/authenticatedUsers", requestValidator) //Devi essere amministratore per bandire gli utenti
app.put(API_V+"/authenticatedUsers/:id", requestValidator) //Devi essere amministratore per bandire gli utenti per id
app.delete(API_V+"/authenticatedUsers/:id", requestValidator) //Devi essere amministratore per eliminare un utente

app.get(API_V+"/registeringUsers/", requestValidator) //Devi essere amministratore per ottenere tutti gli utenti in registrazione
app.delete(API_V+"/registeringUsers/", requestValidator) //Devi essere amministratore per cancellare tutti gli utenti in registrazione
app.delete(API_V+"/registeringUsers/:id", requestValidator) //Devi essere amministratore per cancellare un utente in registrazione per id

app.use(API_V+"/authenticatedUsers", authenticationManager)
app.use(API_V+"/registeringUsers", registrationManager)

app.get("/health", (req, res) => {
  res.json({ healthy: true })
})

app.locals.db = mongoose.connect(process.env.MONGO_URI)
.then(async () => {
    console.log("Connected to Database");
    app.listen(PORT, () => { console.log(`Listening on port ${PORT}`) })
})
.catch ((e) => {
    console.log("Database connection failed", e);
});