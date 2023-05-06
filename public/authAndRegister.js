const { browserSupportsWebAuthn, startRegistration, startAuthentication } =
	SimpleWebAuthnBrowser;

if (!browserSupportsWebAuthn()) {
	alert("This browser does not support FIDO2");
} else {
	document
		.querySelector("#registerButton")
		.addEventListener("click", async () => {
			const elementUsername = document.querySelector("#username");
			if (elementUsername.value == "") {
				alert("Please input username");
				return;
			}
			resetRegistrationData();
			const elementSuccess = document.querySelector("#registerSuccess");
			const elementError = document.querySelector("#registerError");
			const elementDebug = document.querySelector("#registerDebug");

			const optionResponse = await fetch(`/registration/options`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ username: elementUsername.value }),
			});

			let startRegistrationResponse = await callAuthenticatorToRegister(
				optionResponse,
				elementDebug,
				elementError
			);

			const verificationResponse = await fetch(
				`/registration/verification`,
				{
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
					body: JSON.stringify({
						response: startRegistrationResponse,
						username: elementUsername.value,
					}),
				}
			);

			const verificationJSON = await verificationResponse.json();
			printToConsole(
				elementDebug,
				"Server Response",
				JSON.stringify(verificationJSON, null, 2)
			);

			if (verificationJSON && verificationJSON.verified) {
				elementSuccess.innerHTML = `Authenticator registered!`;
			} else {
				elementError.innerHTML = `[Error] Response: <pre>${JSON.stringify(
					verificationJSON
				)}</pre>`;
			}
		});

	// Authentication
	document
		.querySelector("#authenticationButton")
		.addEventListener("click", async () => {
			const elementUsername = document.querySelector("#username");
			if (elementUsername.value == "") {
				alert("Please input username");
				return;
			}
			resetAuthenticationData();
			const elementSuccess = document.querySelector(
				"#authenticationSuccess"
			);
			const elementError = document.querySelector("#authenticationError");
			const elementDebug = document.querySelector("#authenticationDebug");

			const optionsResponse = await fetch(`/authentication/options`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ username: elementUsername.value }),
			});

			let authenticationResponse = await callAuthenticatorToAuthenticate(
				optionsResponse,
				elementDebug,
				elementError
			);

			const verificationResponse = await fetch(
				`/authentication/verification`,
				{
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
					body: JSON.stringify({
						response: authenticationResponse,
						username: elementUsername.value,
					}),
				}
			);

			const verificationJSON = await verificationResponse.json();

			printToConsole(
				elementDebug,
				"Server Response",
				JSON.stringify(verificationJSON, null, 2)
			);

			if (verificationJSON && verificationJSON.verified) {
				elementSuccess.innerHTML = `User authenticated!`;
			} else {
				elementError.innerHTML = `Error: <pre>${JSON.stringify(
					verificationJSON
				)}</pre>`;
			}
		});
}

async function callAuthenticatorToRegister(
	optionResponse,
	elementDebug,
	elementError
) {
	let startRegistrationResponse;
	try {
		const options = await optionResponse.json();

		printToConsole(
			elementDebug,
			"Registration Options",
			JSON.stringify(options, null, 2)
		);

		startRegistrationResponse = await startRegistration(options);
		printToConsole(
			elementDebug,
			"Registration Response",
			JSON.stringify(startRegistrationResponse, null, 2)
		);
	} catch (error) {
		if (error.name === "InvalidStateError") {
			elementError.innerText = "Error: Authenticator already registered";
		} else {
			elementError.innerText = error;
		}

		throw error;
	}
	return startRegistrationResponse;
}

async function callAuthenticatorToAuthenticate(
	optionsResponse,
	elementDebug,
	elementError
) {
	let authenticationResponse;
	try {
		const options = await optionsResponse.json();
		console.log(options);
		printToConsole(
			elementDebug,
			"Authentication Options",
			JSON.stringify(options, null, 2)
		);

		authenticationResponse = await startAuthentication(options);
		printToConsole(
			elementDebug,
			"Authentication Response",
			JSON.stringify(authenticationResponse, null, 2)
		);
	} catch (error) {
		elementError.innerText = error;
		throw new Error(error);
	}
	return authenticationResponse;
}
function resetRegistrationData() {
	const elementSuccess = document.querySelector("#registerSuccess");
	const elementError = document.querySelector("#registerError");
	const elementDebug = document.querySelector("#registerDebug");

	elementSuccess.innerHTML = "";
	elementError.innerHTML = "";
	elementDebug.innerHTML = "";
}
function printToConsole(elemDebug, title, output) {
	if (elemDebug.innerHTML !== "") {
		elemDebug.innerHTML += `\n`;
	}
	elemDebug.innerHTML += `//--------------------------------------------------------\n`;
	elemDebug.innerHTML += `// ${title}\n`;
	elemDebug.innerHTML += `${output}\n`;
	console.log(output);
}

function resetAuthenticationData() {
	const elementSuccess = document.querySelector("#authenticationSuccess");
	const elementError = document.querySelector("#authenticationError");
	const elementDebug = document.querySelector("#authenticationDebug");

	elementSuccess.innerHTML = "";
	elementError.innerHTML = "";
	elementDebug.innerHTML = "";
}
