package org.iotivity.multideviceclient;

import android.util.Log;

import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCDiscoveryHandler;
import org.iotivity.OCEndpoint;
import org.iotivity.oc.OcUtils;

public class ResourceDiscoveryHandler implements OCDiscoveryHandler {

    private static final String TAG = ResourceDiscoveryHandler.class.getSimpleName();

    private OcfDeviceInfo deviceInfo;

    public ResourceDiscoveryHandler(OcfDeviceInfo deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoints, int resourcePropertiesMask) {

        Log.d(TAG, "anchor: " + anchor + ", uri: " + uri);
        OcfResourceInfo resourceInfo = new OcfResourceInfo(anchor, uri, types, interfaceMask, resourcePropertiesMask);

        OCEndpoint ep = endpoints;
        while (ep != null) {
            String endpointStr = OcUtils.endpointToString(ep);
            Log.d(TAG, "\tendpoint: " + endpointStr);
            resourceInfo.addEndpoint(endpointStr);
            ep = ep.getNext();
        }

        deviceInfo.addResourceInfo(resourceInfo);
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}
