package org.iotivity.oc;

import org.iotivity.*;

public class OcObt {

    public OcObt() {
        OCObt.init();
    }

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

    public int performJustWorksOtm(OCUuid uuid, OCObtDeviceStatusHandler otmJustWorksHandler) {
        return OCObt.performJustWorksOtm(uuid, otmJustWorksHandler);
    }

    public int requestRandomPin(OCUuid uuid, OCObtDeviceStatusHandler generateRandomPinHandler) {
        return OCObt.requestRandomPin(uuid, generateRandomPinHandler);
    }

    public int performRandomPinOtm(OCUuid uuid, String pin, OCObtDeviceStatusHandler otmRandomPinHandler) {
        return OCObt.performRandomPinOtm(uuid, pin, pin.length(), otmRandomPinHandler);
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
