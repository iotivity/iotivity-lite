package org.iotivity.oc;

import org.iotivity.*;

public class OcGetRemoteDeviceHandler implements OCResponseHandler {

    private static final String N_KEY = "n";
    private static final String DI_KEY = "di";
    private static final String PIID_KEY = "piid";
    private static final String ICV_KEY = "icv";
    private static final String DMV_KEY = "dmv";

    private OcDiscoverAllHandler discoverAllHandler;

    public OcGetRemoteDeviceHandler(OcDiscoverAllHandler discoverAllHandler) {
        this.discoverAllHandler = discoverAllHandler;
    }

    @Override
    public void handler(OCClientResponse response) {
        OcRepresentation rep = new OcRepresentation(response.getPayload());
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
            if (OCEndpointUtil.toString(endpoint).startsWith("coap:")) {
                if (!OcUtils.doIPDiscoveryAllAtEndpoint(new OcGetRemoteResourcesHandler(device, discoverAllHandler),
                        endpoint)) {
                    System.err.println("Error issuing resource discovery all request for uuid " + di);
                }
            } else {
                System.err.println("Cannot issue resource discovery all request to endpoint "
                        + OCEndpointUtil.toString(endpoint));
            }
        }
    }
}
