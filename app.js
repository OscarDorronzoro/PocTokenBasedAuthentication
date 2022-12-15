import express from 'express';
import crypto from 'crypto';
import { V3, V4 } from 'paseto';
import fs from 'fs';
import jwt from 'jsonwebtoken';

// Set up server
const app = express();
const port = 4001;

app.use(express.json());


// Read ED25519 Private Key
// openssl genpkey -algorithm ed25519 -out keys/privateED.pem
const privateKey = fs.readFileSync('keys/privateED.pem', 'utf8');
const keyPublic = crypto.createPrivateKey(privateKey);

// Read ED25519 Public Key
//openssl pkey -in keys/private.pem -pubout -out keys/publicED.pem
const publicKey = fs.readFileSync('keys/publicED.pem', 'utf8');
const publicKeyPublic = crypto.createPublicKey(publicKey);


// Read local key secret
// crypto.randomBytes(32).toString('base64');
const randomSecret = fs.readFileSync('keys/secret.b64', 'utf8');
const keyLocal = crypto.createSecretKey(randomSecret, 'base64');


// Read RSA Private Key
// openssl genrsa -out keys/privateRSA.pem 4096
const privateKeyRSA = fs.readFileSync('keys/privateRSA.pem', 'utf8');
const keyJWT = crypto.createPrivateKey(privateKeyRSA);

// Read RSA Public Key
// openssl rsa -in keys/privateRSA.pem -outform PEM -pubout -out keys/publicRSA.pem
const publicKeyRSA = fs.readFileSync('keys/publicRSA.pem', 'utf8');
const publicKeyJWT = crypto.createPublicKey(publicKeyRSA);


// Token payload
const payload = {
  username: 'juanPerez',
  role: 'admin'
}


//Generate token for public purpose
async function pasetoPublic() {
  //const key = await V4.generateKey('public')
  const token = await V4.sign(
    payload,
    keyPublic,
    {
      expiresIn: '24 hours'
    }
  )

  return token
}


// Generate token for local purpose
async function pasetoLocal() {
  const token = await V3.encrypt(
    payload,
    keyLocal,
    {
      expiresIn: '24 hours'
    }
  )

  return token
}


// Generate token for JWT with RSA
function jwtRSA() {
  return jwt.sign(payload, privateKeyRSA, { algorithm:'RS256', expiresIn: '24h' });
}

// Generate token for JWT with HMAC
function jwtHMAC() {
  return jwt.sign(payload, keyLocal, { algorithm:'HS256', expiresIn: '24h' });
}


// curl -X POST -d 'username=juanPerez&password=juan123' localhost:4001/api/login | jq '.'
app.post('/api/login', async (req, res) => {
  const tokens = {};
  tokens.public = await pasetoPublic();
  tokens.local = await pasetoLocal();
  tokens.jwtRSA = jwtRSA();
  tokens.jwtHMAC = jwtHMAC();

  res.send(tokens);
});


// curl -X GET -H 'token: v4.public.eyJ1c2VybmFtZSI6Imp1YW5QZXJleiIsInJvbGUiOiJhZG1pbiIsImlhdCI6IjIwMjItMTItMTNUMDM6MTI6NTIuNzgwWiIsImV4cCI6IjIwMjItMTItMTRUMDM6MTI6NTIuNzgwWiJ9nGFFAxqLF18d5YkFqIzXI9_YaBmx46sxEvDpuPRmiyOfQ-HiOuNS9fMsfuLtuoGQ7aR4-iakT4vJTfg1q8zSCQ' localhost:4001/api/users | jq '.'
app.get('/api/users', async (req, res) => {
  const token = req.header('token');

  try {
    const payload = await V4.verify(token, publicKeyPublic);
    res.send(payload);
  }
  catch(err){
    res.sendStatus(401);
  }
});

// curl -X GET -H 'token: v3.local.fEokn9tygMrsFIv5ztThXrZRjsHBEAfTCLcqD0CljtTVV3HIYfLWz0A2o6xEEZFqhQONmDnB-hrXcaHilxxN4i1cwRSb8C4bV1omy8GjdPhzdgpdhUjCFzcV2A8FDWend3aSfc3P2MsWGkhoUWXTKGf2iYC58k3o6dYIqdBfV0waBjcCa9DJJ_cXmh5AvHb_UYU6wxw6vstDShSyX4jiOVtikUsC73rzWC0jV2oeYtA50BQdWyngq_0' localhost:4001/api/articles | jq '.'
app.get('/api/articles', async (req, res) => {
  const token = req.header('token');

  try {
    const payload = await V3.decrypt(token, keyLocal);
    res.send(payload);
  }
  catch(err){
    res.sendStatus(401)
  }
});

// curl -X GET -H 'token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imp1YW5QZXJleiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY3MTA3NDkyNCwiZXhwIjoxNjcxMTYxMzI0fQ.yXa6vvYJhNVVv8xi1g0ItYICh6BPQfowfwM2dhk2u5jTCdYOpc3K-6Y0IlTNBOQjFL3B5lhMpaHLPO1mggzWDxZfqs2opRWiAkZv834LrpQkRcGY_d7aiJTawm-V9QPOW2AnsyK-f26B-sfD-z3cvwZfLKctN_c78RmuLdw-RWDYJENUIBmUF4d53alplEfVUIYlG1GTN79i6XzztOnXTnFXlvwAGLIfJqN9msX-Kg3hikXnPJLh4plk1ZyB1QC6fQ2zE49xjXJf48GOwGPY5l68n0rfGqIuGFtFU_BZNL4PGDQjHAAptHyTPsX80bh_TGlfBzw9zTIRgBMyFi6pHfcaxF_35eyKEZYKP3l0hD3U-mjNvGyRZJjmShBFJST_skBVjaetA2P52DUJtQrsfOydE7epm-5b8wCAWHo5yn2iTiXZ8vzfJ2L9oImYWkru0OKix0QXrAPddp2n0SkZPnRSWP-6JzF_Hi__chEXdR6ofAuF7tRkjRBOheCync6NPUFuVyCRe7cVuHtGrf6yuwtMBn7_vrpM2YnGMduUsQqoIr1imKOjtFzvLx-5c0zSZMYi8O4aVetTmSdTnMeKIPi0Fg_zas8_HqsrhyZpGbfBj6T4fxbDSrN1x5JLlkqYlpe85fgliC_1mxdPbXHWORbJg0tley13orY4862NgGU' localhost:4001/api/providers | jq '.'
app.get('/api/providers', async (req, res) => {
  const token = req.header('token');

  try {
    const payload = jwt.verify(token, publicKeyJWT, { algorithms: ['RS256'] });
    res.send(payload);
  }
  catch(err){
    res.sendStatus(401);
  }
});

// curl -X GET -H 'token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imp1YW5QZXJleiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY3MTA3NTgyOCwiZXhwIjoxNjcxMTYyMjI4fQ.XCCFvsTQaIPH-WFvjuCNHvIPeW7GRmvXpjNIYOCUNY8' localhost:4001/api/categories | jq '.'
app.get('/api/categories', async (req, res) => {
  const token = req.header('token');

  try {
    const payload = jwt.verify(token, keyLocal, { algorithms: ['HS256'] });
    res.send(payload);
  }
  catch(err){
    res.sendStatus(401);
  }
});


app.server = app.listen(port, (err) => {
  if (err) {
    console.log(err);
  } else {
    console.log(`Running on port ${port}`);
  }
});










