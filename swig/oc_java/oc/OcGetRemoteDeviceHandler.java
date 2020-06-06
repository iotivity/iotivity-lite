package org.iotivity.oc;

import org.iotivity.*;

class OcGetRemoteDeviceHandler implements OCResponseHandler {

    private static final String N_KEY = "n";
    private static final String DI_KEY = "di";
    private static final String PIID_KEY = "piid";
    private static final String ICV_KEY = "icv";
    private static final String DMV_KEY = "dmv";

    private OcDeviceDiscoveryHandler deviceDiscoveryHandler;

    public OcGetRemoteDeviceHandler(OcDeviceDiscoveryHandler deviceDiscoveryHandler) {
        this.deviceDiscoveryHandler = deviceDiscoveryHandler;
    }

    @Override
    public void handler(OCClientResponse response) {
        OcRepresentation rep = null;
        try {
            rep = new OcRepresentation(response.getPayload());
        } catch (Exception e) {
            System.err.println("Failed to get representation from client response, " + e.getMessage());
            return;
        }

        String n = null;
        String di = null;
        String piid = null;
        String icv = null;
        String dmv = null;
        while (rep != null) {
            try {
                if (N_KEY.equals(rep.getKey())) {
                    n = rep.getString(N_KEY);
                }
                if (DI_KEY.equals(rep.getKey())) {
                    di = rep.getString(DI_KEY);
                }
                if (PIID_KEY.equals(rep.getKey())) {
                    piid = rep.getString(PIID_KEY);
                }
                if (ICV_KEY.equals(rep.getKey())) {
                    icv = rep.getString(ICV_KEY);
                }
                if (DMV_KEY.equals(rep.getKey())) {
                    dmv = rep.getString(DMV_KEY);
                }
            } catch (OcCborException e) {
                System.err.println(e.getMessage());
            }
            rep = rep.getNext();
        }

        if ((di != null) && (n != null)) {
            OcRemoteDevice device = new OcRemoteDevice(OCUuidUtil.stringToUuid(di), n, piid, icv, dmv);

            OCEndpoint endpoint = response.getEndpoint();
            while (endpoint != null) {
                if (OcUtils.endpointToString(endpoint).startsWith("coap://")) {
                    boolean retVal = OcUtils.doIPDiscoveryAllAtEndpoint(
                            new OcGetRemoteResourcesHandler(device, deviceDiscoveryHandler), endpoint);
                    if (retVal) {
                        return;
                    }
                    System.err.println("Error issuing resource discovery all request for uuid " + di + " at endpoint "
                            + OcUtils.endpointToString(endpoint));
                }

                endpoint = endpoint.getNext();
            }

            System.err.println("Cannot issue resource discovery all request to any 'coap://' endpoint");
            return;
        }

        System.err.println("'di' or 'n' cannot be null");
    }
}
