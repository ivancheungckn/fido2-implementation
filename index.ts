import fs from "fs";
import https from "https";

import base64url from "base64url";
import express from "express";
import session from "express-session";
import memoryStore from "memorystore";
import cbor from "cbor";
import type {
	AuthenticationResponseJSON,
	AuthenticatorDevice,
	RegistrationResponseJSON,
} from "@simplewebauthn/typescript-types";

import type {
	GenerateAuthenticationOptionsOpts,
	GenerateRegistrationOptionsOpts,
	VerifiedAuthenticationResponse,
	VerifiedRegistrationResponse,
	VerifyAuthenticationResponseOpts,
	VerifyRegistrationResponseOpts,
} from "@simplewebauthn/server";
import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoUint8Array } from "@simplewebauthn/server/helpers";

interface User {
	id: string;
	username: string;
	devices: AuthenticatorDevice[];
}

declare module "express-session" {
	interface SessionData {
		currentChallenge?: string;
	}
}

const app = express();
const MemoryStore = memoryStore(session);

const rpID = "projectivancheung.online";

app.use(express.static("./public/"));
app.use(express.json());
app.use(
	session({
		secret: "this_is_secret",
		saveUninitialized: true,
		resave: false,
		cookie: {
			maxAge: 86400000,
			httpOnly: true,
		},
		store: new MemoryStore({
			checkPeriod: 86_400_000, // expire after 24hr
		}),
	})
);

const domain = `https://${rpID}`;

const userDB: { [username: string]: User } = {};

// this method to generate registration challenge
app.post("/registration/options", (req: any, res) => {
	const username = req.body.username;
	const devices = [] as any;
	const user = userDB[username];
	if (user) {
		res.send({ registered: true });
		return;
	}

	let userId = new Date().getMilliseconds().toString();

	const options: GenerateRegistrationOptionsOpts = {
		rpName: "FIDO2 service",
		rpID,
		userID: userId,
		userName: username,
		timeout: 60000,
		attestationType: "none",
		excludeCredentials: devices.map((dev: any) => ({
			id: dev.credentialID,
			type: "public-key",
			transports: dev.transports,
		})),
		authenticatorSelection: {
			residentKey: "discouraged",
		},
		//ES256
		supportedAlgorithmIDs: [-7],
	};

	const optionsResult = generateRegistrationOptions(options);
	req.session.userId = userId;
	req.session.currentChallenge = optionsResult.challenge;

	res.send(optionsResult);
	return;
});

app.post("/registration/verification", async (req: any, res) => {
	const body: RegistrationResponseJSON = req.body.response;
	const username = req.body.username;
	let attestationObject = body.response.attestationObject;
	// need to convert to base64 encode string
	// attestationObject =
	// 	attestationObject.replace(/\-/g, "+").replace(/_/g, "/") +
	// 	"==".substring(0, (3 * attestationObject.length) % 4);

	// // do a base64 decode
	// var attCbor = Buffer.from(attestationObject, "base64");

	// console.log(attCbor);
	// const d = cbor.Decoder.decodeAllSync(attCbor);
	// console.log(d);
	const expectedChallenge = req.session.currentChallenge;
	const expectedUserId = req.session.userId;
	let verification: VerifiedRegistrationResponse;
	try {
		const options: VerifyRegistrationResponseOpts = {
			response: body,
			expectedChallenge: `${expectedChallenge}`,
			expectedOrigin: domain,
			expectedRPID: rpID,
			requireUserVerification: true,
		};
		verification = await verifyRegistrationResponse(options);
	} catch (error) {
		const _error = error as Error;
		console.error(_error);
		return res.status(400).send({ error: _error.message });
	}

	const { verified, registrationInfo } = verification;

	if (verified && registrationInfo) {
		const { credentialPublicKey, credentialID, counter } = registrationInfo;
		userDB[username] = {
			id: expectedUserId,
			username: username,
			devices: [],
		};
		const user = userDB[username];
		const existingDevice = user.devices.find((device) =>
			isoUint8Array.areEqual(device.credentialID, credentialID)
		);

		if (!existingDevice) {
			const newDevice: AuthenticatorDevice = {
				counter,
				credentialPublicKey,
				transports: body.response.transports,
				credentialID,
			};
			user.devices.push(newDevice);
		}
	}

	req.session.currentChallenge = undefined;
	req.session.username = undefined;

	res.send({ verified });
});

//authentication
app.post("/authentication/options", (req: any, res) => {
	const username = req.body.username;
	const user = userDB[username];
	if (!user) {
		res.send({ registered: false });
		return;
	}
	const opts: GenerateAuthenticationOptionsOpts = {
		timeout: 60000,
		rpID,
		allowCredentials: user.devices.map((dev) => ({
			id: dev.credentialID,
			type: "public-key",
			transports: dev.transports,
		})),
		userVerification: "required",
	};

	const options = generateAuthenticationOptions(opts);

	req.session.currentChallenge = options.challenge;

	res.send(options);
});

app.post("/authentication/verification", async (req: any, res) => {
	const body: AuthenticationResponseJSON = req.body.response;
	const username = req.body.username;
	const user = userDB[username];

	const expectedChallenge = req.session.currentChallenge;

	let authenticator;
	const bodyCredIDBuffer = base64url.toBuffer(body.rawId);

	for (const dev of user.devices) {
		if (isoUint8Array.areEqual(dev.credentialID, bodyCredIDBuffer)) {
			authenticator = dev;
			break;
		}
	}

	if (!authenticator) {
		return res
			.status(400)
			.send({ error: "Authenticator is not registered with this site" });
	}

	let verification: VerifiedAuthenticationResponse;
	try {
		const opts: VerifyAuthenticationResponseOpts = {
			response: body,
			expectedChallenge: `${expectedChallenge}`,
			expectedOrigin: domain,
			requireUserVerification: true,
			expectedRPID: rpID,
			authenticator: authenticator,
		};
		verification = await verifyAuthenticationResponse(opts);
	} catch (error) {
		const _error = error as Error;
		console.error(_error);
		return res.status(400).send({ error: _error.message });
	}

	const { verified, authenticationInfo } = verification;

	if (verified) {
		authenticator.counter = authenticationInfo.newCounter;
	}

	req.session.currentChallenge = undefined;
	req.session.username = undefined;
	res.send({ verified });
});

//need to update
const host = "192.168.1.167";
const port = 443;

https
	.createServer(
		{
			key: fs.readFileSync(`./${rpID}.key`),
			cert: fs.readFileSync(`./${rpID}.crt`),
		},
		app
	)
	.listen(port, host, () => {
		console.log(`Server open at ${domain} (${host}:${port})`);
	});
