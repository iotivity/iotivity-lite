package org.iotivity.oc;

import org.iotivity.*;

public class OcGetRemoteResourcesHandler implements OCDiscoveryAllHandler {

    private OcRemoteDevice device;
    private OcDiscoverAllHandler discoverAllHandler;

    public OcGetRemoteResourcesHandler(OcRemoteDevice device, OcDiscoverAllHandler discoverAllHandler) {
        this.device = device;
        this.discoverAllHandler = discoverAllHandler;
    }

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoints,
            int resourcePropertiesMask, boolean more) {

        OcRemoteResource resource = new OcRemoteResource(anchor, uri, types, interfaceMask, resourcePropertiesMask);

        OCEndpoint ep = endpoints;
        while (ep != null) {
            String endpointStr = OcUtils.endpointToString(ep);
            resource.addEndpoint(endpointStr);
            ep = ep.getNext();
        }

        device.addResource(resource);

        if (!more) {
            discoverAllHandler.discoveredDevice(device);

            return OCDiscoveryFlags.OC_STOP_DISCOVERY;
        }

        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}
