package org.iotivity.oc;

import org.iotivity.*;

class OcGetRemoteResourcesHandler implements OCDiscoveryAllHandler {

    private OcRemoteDevice device;
    private OcDeviceDiscoveryHandler deviceDiscoveryHandler;

    public OcGetRemoteResourcesHandler(OcRemoteDevice device, OcDeviceDiscoveryHandler deviceDiscoveryHandler) {
        this.device = device;
        this.deviceDiscoveryHandler = deviceDiscoveryHandler;
    }

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoints,
            int resourcePropertiesMask, boolean more) {

        OcRemoteResource resource = new OcRemoteResource(anchor, uri, types, interfaceMask, resourcePropertiesMask);

        OCEndpoint ep = endpoints;
        while (ep != null) {
            resource.addEndpoint(OCEndpointUtil.copy(ep));
            ep = ep.getNext();
        }

        device.addResource(resource);

        if (!more) {
            deviceDiscoveryHandler.discoveredDevice(device);

            return OCDiscoveryFlags.OC_STOP_DISCOVERY;
        }

        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}
