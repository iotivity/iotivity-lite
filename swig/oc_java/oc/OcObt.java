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

    public int discoverOwnedDevices(OCObtDiscoveryHandler ownedDeviceHandler) {
        return OCObt.discoverOwnedDevices(ownedDeviceHandler);
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

    public int provisionPairwiseCredentials(OCUuid uuid1, OCUuid uuid2,
            OCObtStatusHandler provisionCredentialsHandler) {
        return OCObt.provisionPairwiseCredentials(uuid1, uuid2, provisionCredentialsHandler);
    }

    public int provisionAce(OCUuid uuid, OcSecurityAce securityAce, OCObtDeviceStatusHandler provisionAce2Handler) {
        OCSecurityAce nativeSecurityAce = securityAce.getNativeSecurityAce();
        return OCObt.provisionAce(uuid, nativeSecurityAce, provisionAce2Handler);
    }

    public int deviceHardReset(OCUuid uuid, OCObtDeviceStatusHandler resetDeviceHandler) {
        return OCObt.deviceHardReset(uuid, resetDeviceHandler);
    }
}
