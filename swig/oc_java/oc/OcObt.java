package org.iotivity.oc;

import org.iotivity.*;

/**
 * OcObt provides access to all the methods necessary for an On Boarding Tool.
 */
public class OcObt {

    /**
     * Creates and initializes an on boarding tool instance.
     */
    public OcObt() {
        OCObt.init();
    }

    /**
     * Ends the lifetime of an on boarding tool instance.
     * <p>
     * Once shutdown() is called, this OcObt instance should not be used again.
     */
    public void shutdown() {
        OCObt.shutdown();
    }

    public int discoverUnownedDevices(OCObtDiscoveryHandler unownedDeviceHandler) {
        return OCObt.discoverUnownedDevices(unownedDeviceHandler);
    }

    public int discoverUnownedDevicesRealmLocalIPv6(OCObtDiscoveryHandler unownedDeviceHandler) {
        return OCObt.discoverUnownedDevicesRealmLocalIPv6(unownedDeviceHandler);
    }

    public int discoverUnownedDevicesSiteLocalIPv6(OCObtDiscoveryHandler unownedDeviceHandler) {
        return OCObt.discoverUnownedDevicesSiteLocalIPv6(unownedDeviceHandler);
    }

    public int discoverOwnedDevices(OCObtDiscoveryHandler ownedDeviceHandler) {
        return OCObt.discoverOwnedDevices(ownedDeviceHandler);
    }

    public int discoverOwnedDevicesRealmLocalIPv6(OCObtDiscoveryHandler ownedDeviceHandler) {
        return OCObt.discoverOwnedDevicesRealmLocalIPv6(ownedDeviceHandler);
    }

    public int discoverOwnedDevicesSiteLocalIPv6(OCObtDiscoveryHandler ownedDeviceHandler) {
        return OCObt.discoverOwnedDevicesSiteLocalIPv6(ownedDeviceHandler);
    }

    public int discoverAllResources(OCUuid uuid, OCDiscoveryAllHandler discoverHandler) {
        return OCObt.discoverAllResources(uuid, discoverHandler);
    }
    public int performJustWorksOtm(OCUuid uuid, OCObtDeviceStatusHandler otmJustWorksHandler) {
        return OCObt.performJustWorksOtm(uuid, otmJustWorksHandler);
    }

    public int requestRandomPin(OCUuid uuid, OCObtDeviceStatusHandler generateRandomPinHandler) {
        return OCObt.requestRandomPin(uuid, generateRandomPinHandler);
    }

    public int performRandomPinOtm(OCUuid uuid, String pin, OCObtDeviceStatusHandler otmRandomPinHandler) {
        return OCObt.performRandomPinOtm(uuid, pin, otmRandomPinHandler);
    }

    public int performCertOtm(OCUuid uuid, OCObtDeviceStatusHandler otmCertHandler) {
        return OCObt.performCertOtm(uuid, otmCertHandler);
    }

    public int provisionPairwiseCredentials(OCUuid uuid1, OCUuid uuid2,
            OCObtStatusHandler provisionCredentialsHandler) {
        return OCObt.provisionPairwiseCredentials(uuid1, uuid2, provisionCredentialsHandler);
    }

    public int provisionIdentityCertificate(OCUuid uuid, OCObtStatusHandler provisionCertHandler) {
        return OCObt.provisionIdentityCertificate(uuid, provisionCertHandler);
    }

    public int provisionRoleCertificate(OCRole role, OCUuid uuid, OCObtStatusHandler provisionCertHandler) {
        return OCObt.provisionRoleCertificate(role, uuid, provisionCertHandler);
    }

    public int provisionAce(OCUuid uuid, OcSecurityAce securityAce, OCObtDeviceStatusHandler provisionAce2Handler) {
        OCSecurityAce nativeSecurityAce = securityAce.getNativeSecurityAce();
        return OCObt.provisionAce(uuid, nativeSecurityAce, provisionAce2Handler);
    }

    public int provisionRoleWildcardAce(OCUuid uuid, String role, String authority,
            OCObtDeviceStatusHandler provisionAceHandler) {
        return OCObt.provisionRoleWildcardAce(uuid, role, authority, provisionAceHandler);
    }

    public int provisionAuthWildcardAce(OCUuid uuid, OCObtDeviceStatusHandler provisionAceHandler) {
        return OCObt.provisionAuthWildcardAce(uuid, provisionAceHandler);
    }

    public OCCreds retrieveOwnCreds() {
        return OCObt.retrieveOwnCreds();
    }

    public int deleteOwnCredByCredId(int credid){
        return OCObt.deleteOwnCredByCredId(credid);
    }

    public int retrieveCreds(OCUuid subjectUuid, OCObtCredsHandler obtCredsHandler) {
        return OCObt.retrieveCreds(subjectUuid, obtCredsHandler);
    }

    public void freeCreds(OCCreds creds) {
        OCObt.freeCreds(creds);
    }

    public int deleteCredByCredId(OCUuid uuid, int credid, OCObtStatusHandler obtStatusHandler) {
        return OCObt.deleteCredByCredId(uuid, credid, obtStatusHandler);
    }

    public int retrieveAcl(OCUuid uuid, OCObtAclHandler obtAclHandler) {
        return OCObt.retrieveAcl(uuid, obtAclHandler);
    }

    public void freeAcl(OCSecurityAcl acl) {
        OCObt.freeAcl(acl);
    }

    public int deleteAceByAceId(OCUuid uuid, int aceid, OCObtStatusHandler obtStatusHandler) {
        return OCObt.deleteAceByAceId(uuid, aceid, obtStatusHandler);
    }

    public int deviceHardReset(OCUuid uuid, OCObtDeviceStatusHandler resetDeviceHandler) {
        return OCObt.deviceHardReset(uuid, resetDeviceHandler);
    }

    public OCRole addRoleId(OCRole roles, String role, String authority) {
        return OCObt.addRoleId(roles, role, authority);
    }

    public void freeRoleId(OCRole roles) {
        OCObt.freeRoleId(roles);
    }
}
