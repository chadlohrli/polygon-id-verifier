const axios = require('axios')
const cors = require('cors')
const {auth, resolver, loaders} = require('@iden3/js-iden3-auth')
const express = require('express');

require('dotenv').config()

const corsOptions ={
   origin:'*', 
   credentials:true,            
   optionSuccessStatus:200,
}

const getRawBody = require('raw-body')

const MUMBAI_RPC = process.env.MUMBAI_RPC
const MUMBAI_CONTRACT = "0x46Fd04eEa588a3EA7e9F055dd691C688c4148ab3"
const CALLBACK_HOST = process.env.CALLBACK_HOST

const app = express();
app.use(cors(corsOptions));
const port = 8080;

app.use(express.static('static'));

app.get("/api/sign-in", (req, res) => {
    console.log('get Auth Request');
    GetAuthRequest(req,res);
});

app.post("/api/callback", (req, res) => {
    console.log('callback');
    Callback(req,res);
});

app.listen(port, () => {
    console.log('server running on port 8080');
});

const requestMap = new Map();

async function GetAuthRequest(req,res) {
  // Audience is verifier id
  const hostUrl = CALLBACK_HOST;
  const sessionId = 1;
  const callbackURL = "/api/callback"
  const audience = "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"

  const uri = `${hostUrl}${callbackURL}?sessionId=${sessionId}`;

  // Generate request for basic authentication
  const request = auth.createAuthorizationRequestWithMessage(
    'test flow',
    'message to sign',
    audience,
    uri,
  );
        
  request.id = '7f38a193-0918-4a48-9fac-36adfdb8b542';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542';

  // Add request for a specific proof
  const proofRequest = {
    id: 1,
    circuit_id: "credentialAtomicQuerySig",
    rules: {
      query: {
        allowedIssuers: ["*"],
        req: {
          birthday: {
            $lt: 20010101
          }
        },
        schema: {
          url:
            "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld",
          type: "KYCAgeCredential"
        }
      }
    }
  };

  const scope = request.body.scope ?? [];
  request.body.scope = [...scope, proofRequest];

  // Store auth request in map associated with session ID
  requestMap.set(`${sessionId}`, request);
  console.log(`request: ${request}`)

  return res.status(200).send(request);
}

async function Callback(req,res) {

  // Get session ID from request
  const sessionId = req.query.sessionId;

  // get JWZ token params from the post request
  const raw = await getRawBody(req);
  const tokenStr = raw.toString().trim();

  console.log(`tokenStr: ${tokenStr}`)

  // fetch authRequest from sessionID
  const authRequest = requestMap.get(`${sessionId}`);

  console.log(`authRequest: ${authRequest}`)
				
  // Locate the directory that contains circuit's verification keys
  const verificationKeyloader = new loaders.FSKeyLoader('./keys');
  const sLoader = new loaders.UniversalSchemaLoader('ipfs.io');

  // Add Polygon RPC node endpoint - needed to read on-chain state and identity state contract address
  const ethStateResolver = new resolver.EthStateResolver(MUMBAI_RPC, MUMBAI_CONTRACT);

  // EXECUTE VERIFICATION
  const verifier = new auth.Verifier(
  verificationKeyloader,
  sLoader, ethStateResolver,
  );

  try {
    authResponse = await verifier.fullVerify(tokenStr, authRequest);
  } catch (error) {
    console.log(error)
    return res.status(500).send(error);
  }
  console.log(authResponse)

  /*
  axios.post('http://localhost:3000/api/callback', authResponse)
  .then((res) => {
      console.log(`Status: ${res.status}`);
      console.log('Student Info: ', res.data);
  }).catch((err) => {
      console.error(err);
  });
  */

  return res.status(200).send("user with ID: " + authResponse.from + " Succesfully authenticated");
}

