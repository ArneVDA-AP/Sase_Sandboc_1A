{
	"id": "4be637ed-deac-447d-821e-929183bff235",
	"deletedDateTime": null,
	"appId": "11803ee8-eb15-462c-a286-5415c17a29c6",
	"applicationTemplateId": null,
	"disabledByMicrosoftStatus": null,
	"createdByAppId": "18ed3507-a475-4ccb-b669-d66bc9f2a36e",
	"createdDateTime": "2026-05-29T23:46:44Z",
	"displayName": "2ITCSC1A-Netbird-Sandbox",
	"description": null,
	"groupMembershipClaims": "ApplicationGroup",
	"identifierUris": [],
	"isDeviceOnlyAuthSupported": null,
	"isDisabled": null,
	"isFallbackPublicClient": null,
	"nativeAuthenticationApisEnabled": null,
	"notes": null,
	"publisherDomain": "apstudentantwerp.onmicrosoft.com",
	"serviceManagementReference": null,
	"signInAudience": "AzureADMyOrg",
	"tags": [],
	"tokenEncryptionKeyId": null,
	"samlMetadataUrl": null,
	"defaultRedirectUri": null,
	"certification": null,
	"requestSignatureVerification": null,
	"addIns": [],
	"api": {
		"acceptMappedClaims": null,
		"knownClientApplications": [],
		"requestedAccessTokenVersion": null,
		"oauth2PermissionScopes": [],
		"preAuthorizedApplications": []
	},
	"appRoles": [],
	"info": {
		"logoUrl": null,
		"marketingUrl": null,
		"privacyStatementUrl": null,
		"supportUrl": null,
		"termsOfServiceUrl": null
	},
	"keyCredentials": [],
	"optionalClaims": {
		"accessToken": [
			{
				"additionalProperties": [
					"cloud_displayname"
				],
				"essential": false,
				"name": "groups",
				"source": null
			}
		],
		"idToken": [
			{
				"additionalProperties": [
					"cloud_displayname"
				],
				"essential": false,
				"name": "groups",
				"source": null
			}
		],
		"saml2Token": []
	},
	"parentalControlSettings": {
		"countriesBlockedForMinors": [],
		"legalAgeGroupRule": "Allow"
	},
	"passwordCredentials": [
		{
			"customKeyIdentifier": null,
			"displayName": "zitadel-sandbox-federation",
			"endDateTime": "2028-05-28T23:49:25.079Z",
			"hint": "ewk",
			"keyId": "e19dd4c3-436f-4889-a25f-5ffdef9e8671",
			"secretText": null,
			"startDateTime": "2026-05-29T23:49:25.079Z"
		}
	],
	"publicClient": {
		"redirectUris": []
	},
	"requiredResourceAccess": [
		{
			"resourceAppId": "00000003-0000-0000-c000-000000000000",
			"resourceAccess": [
				{
					"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
					"type": "Scope"
				}
			]
		}
	],
	"verifiedPublisher": {
		"displayName": null,
		"verifiedPublisherId": null,
		"addedDateTime": null
	},
	"web": {
		"homePageUrl": null,
		"logoutUrl": null,
		"redirectUris": [
			"https://netbird.sandbox.local/ui/login/login/externalidp/callback"
		],
		"implicitGrantSettings": {
			"enableAccessTokenIssuance": false,
			"enableIdTokenIssuance": false
		},
		"redirectUriSettings": [
			{
				"uri": "https://netbird.sandbox.local/ui/login/login/externalidp/callback",
				"index": null
			}
		]
	},
	"servicePrincipalLockConfiguration": {
		"isEnabled": true,
		"allProperties": true,
		"credentialsWithUsageVerify": true,
		"credentialsWithUsageSign": true,
		"identifierUris": false,
		"tokenEncryptionKeyId": true
	},
	"spa": {
		"redirectUris": []
	}
}
