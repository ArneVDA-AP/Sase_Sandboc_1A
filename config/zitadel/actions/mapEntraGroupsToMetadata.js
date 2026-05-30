/**
 * mapEntraGroupsToMetadata
 *
 * Doel: map Entra security groups -> interne SASE persona-namen en schrijf
 *       het resultaat naar user-metadata (sleutel: sase_groups).
 *       Allowlist (fail-closed): niet-gemapte groepen worden overgeslagen.
 *
 * Zitadel:  v2.64.1 (Actions v1, goja, ECMAScript 5.1+)
 * Flow:     External Authentication
 * Trigger:  Post Authentication
 * Koppeling: Actions -> Flows -> External Authentication -> Post Authentication
 * Action-naam in console MOET gelijk zijn aan de functienaam: mapEntraGroupsToMetadata
 * allowed-to-fail: AAN (bewust — fail-closed wordt op de policy-laag afgedwongen, niet hier)
 *
 * Context: Verslag 30, Bevinding 30.16. Brugpartner: setGroupsClaimFromMetadata.js
 * NB: ctx.getClaim / ctx.claimsJSON zijn DIRECTE ctx-velden in External Auth;
 *     ctx.v1.authError / ctx.v1.externalUser zitten onder v1 (gemengde API-vorm).
 */
let logger = require("zitadel/log");

function mapEntraGroupsToMetadata(ctx, api) {
    if (ctx.v1.authError !== "none") {
        return;
    }

    var allow = {
        "2ITCSC1A-Studenten": "Studenten",
        "2ITCSC1A-Docenten":  "Docenten",
        "2ITCSC1A-Admins":    "Admins"
    };

    var entraGroups = ctx.getClaim("groups");
    var mapped = [];

    if (Array.isArray(entraGroups)) {
        for (var i = 0; i < entraGroups.length; i++) {
            var internal = allow[entraGroups[i]];
            if (internal !== undefined) {
                mapped.push(internal);
            }
        }
    }

    logger.log("SASE map: entra=" + JSON.stringify(entraGroups) + " mapped=" + JSON.stringify(mapped));
    api.v1.user.appendMetadata("sase_groups", mapped.join(","));
}
