/**
 * setGroupsClaimFromMetadata
 *
 * Doel: lees sase_groups (platte komma-string) uit user-metadata en zet die
 *       als platte groups-claim op het token dat NetBird valideert.
 *       Fail-closed: lege/afwezige metadata = geen claim.
 *
 * Zitadel:  v2.64.1 (Actions v1, goja, ECMAScript 5.1+)
 * Flow:     Complement Token
 * Triggers: Pre Userinfo creation  EN  Pre access token creation  (beide koppelen)
 * Koppeling: Actions -> Flows -> Complement Token -> beide triggers
 * Action-naam in console MOET gelijk zijn aan de functienaam: setGroupsClaimFromMetadata
 * allowed-to-fail: AAN (bewust — zie Verslag 30 prioriteit 2)
 *
 * Context: Verslag 30, Bevinding 30.15/30.16. Brugpartner: mapEntraGroupsToMetadata.js
 * NB (Bevinding 30.15): getMetadata() geeft de waarde BINNEN een action al gedecodeerd
 *     terug als platte string ("Studenten,Admins") — GEEN base64, GEEN quote-wrap.
 *     De base64-codering geldt alleen voor de metadata zoals die in het token verschijnt.
 *     Daarom volstaat raw.split(",") — geen atob, geen JSON.parse.
 */
let logger = require("zitadel/log");

function setGroupsClaimFromMetadata(ctx, api) {
    var md = ctx.v1.user.getMetadata();
    if (md === undefined || md.metadata === undefined) {
        logger.log("SASE claim: geen metadata");
        return;
    }

    var raw = null;
    for (var i = 0; i < md.metadata.length; i++) {
        if (md.metadata[i].key === "sase_groups") {
            raw = md.metadata[i].value;
            break;
        }
    }
    if (raw === null) {
        logger.log("SASE claim: sase_groups ontbreekt");
        return;
    }

    var groups = raw.split(",").filter(function (g) { return g.length > 0; });
    logger.log("SASE claim: setting groups=" + JSON.stringify(groups));
    if (groups.length > 0) {
        api.v1.claims.setClaim("groups", groups);
    }
}
