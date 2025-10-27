// index.js
import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import fs from 'fs';
import path from 'path';
import { IdentityProvider, ServiceProvider, setSchemaValidator } from 'samlify';
import validator from '@authenio/samlify-node-xmllint';
import { fileURLToPath } from 'url';
import 'dotenv/config';


setSchemaValidator(validator);

const secret = process.env.SESSION_SECRET;
const idpEntityId = process.env.IDP_ENTITY_ID;
const privateKeyPath = process.env.IDP_PRIVATE_KEY_PATH;
const publicCertPath = process.env.IDP_PUBLIC_CERT_PATH;
const idpPrivateKey = Buffer.from(process.env.IDP_PRIVATE_KEY, 'base64').toString('utf-8');
const idpPublicCert = Buffer.from(process.env.IDP_PUBLIC_CERT, 'base64').toString('utf-8');
const spCert = Buffer.from(process.env.SP_CERT, 'base64').toString('utf-8');
const baseURL = "https://improved-fishstick-6aabdda5d171.herokuapp.com/"


const app = express();
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: secret,
  resave: false,
  saveUninitialized: true,
}));

// === Configure your Identity Provider (this app) ===
const idp = IdentityProvider({
  entityID: idpEntityId,   // change to your public IdP metadata URL (ngrok or domain)
  signingCert: idpPublicCert.toString(),
  privateKey: idpPrivateKey.toString(),
  singleSignOnService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: `${baseURL}/saml/sso`, // replace with your public url + route
  }],
  singleLogoutService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: `${baseURL}/saml/logout`,
  }],
  // optional: nameID formats and more
});

// === Configure a Service Provider | ClickUp ===
// You'll replace the placeholders with ClickUp's SP EntityID and ACS URL (Assertion Consumer Service)
// For now, put placeholders which you'll update after you get ClickUp metadata.
const sp = ServiceProvider({
  entityID: 'https://api.clickup.com/v1/team/36226098/saml', // placeholder — replace with ClickUp SP entity ID
  assertionConsumerService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'https://api.clickup.com/v1/team/36226098/saml/consume', // placeholder — replace with ClickUp ACS URL
  }],
  signingCert: spCert, 
  // optionally set wantAuthnRequestsSigned, signature algorithms, etc.
});

// === Expose IdP metadata for ClickUp to consume ===
app.get('/metadata', (req, res) => {
  res.type('application/xml');
  res.send(idp.getMetadata());
});

// === Simple login page for developer/testing ===
app.get('/login', (req, res) => {
  // render a simple form to input username; on submit we'll "authenticate" locally
  res.render('login', { relayState: req.query.RelayState || '', samlRequest: req.query.SAMLRequest || '' });
});

app.post('/login', async (req, res) => {
  // Authenticate user (replace with real auth)
  const username = req.body.username || 'sso+pbishop@clickup.com';
  // store session
  req.session.user = { id: username, email: username, firstName: 'Peter', lastName: 'SSO' };

  // after login, redirect to same /saml/sso flow with original query (RelayState, SAMLRequest)
  // in a real flow, the SP initiates and provides SAMLRequest/RelayState; we must respond to that.
  const { relayState, samlRequest } = req.body;
  // For simplicity, redirect to "/saml/sso" to resume flow, preserving RelayState and SAMLRequest
  res.redirect(`/saml/sso?RelayState=${encodeURIComponent(relayState || '')}&SAMLRequest=${encodeURIComponent(samlRequest || '')}`);
});

// === SP-initiated SSO endpoint (IdP SSO entrypoint) ===
// ClickUp will redirect here with SAMLRequest (HTTP-Redirect) when user clicks "SSO"
app.get('/saml/sso', async (req, res) => {
  // If user not logged in locally, send to login page
  if (!req.session.user) {
    // forward the SAMLRequest and RelayState to the login page so we can resume after auth
    return res.redirect(`/login?SAMLRequest=${encodeURIComponent(req.query.SAMLRequest || '')}&RelayState=${encodeURIComponent(req.query.RelayState || '')}`);
  }

  // parse the incoming AuthnRequest (optional) — samlify supports parsing requests from SP
  // We'll create and send a SAML Response (assertion) to the SP's ACS (POST binding).
  try {
    // Create login response to SP
    const now = Math.floor(Date.now() / 1000);
    // attributes for the assertion: adjust according to ClickUp mapping (email required)
    const attributes = {
      email: req.session.user.email,
      firstName: req.session.user.firstName,
      lastName: req.session.user.lastName,
    };

    // Create SAML response and auto-sign
    const samlResponse = await idp.createLoginResponse(sp, 'post', {
      // the user profile
      authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      subject: {
        nameID: req.session.user.email,
        nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      },
      attributes,
    }, 'https://app.clickup.com/saml/acs'); // replace with actual ACS from ClickUp

    // Respond with an HTML form that auto-submits to the SP's ACS (HTTP-POST binding)
    res.type('html').send(samlResponse);
  } catch (err) {
    console.error('Error creating SAML response', err);
    res.status(500).send('SAML response error');
  }
});

// === Assertion Consumer Service (if you need to accept responses from SP or handle logout) ===
app.post('/saml/acs', (req, res) => {
  // If your IdP initiates, you may not need this. Usually SP posts to ACS on SP side.
  res.send('ACS endpoint on IdP (not typically used)');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`IdP running on ${baseURL}`);
  console.log(`Metadata available at ${baseURL}/metadata`);
});
