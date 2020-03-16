package org.iotivity.simpleclient;

import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCDiscoveryHandler;
import org.iotivity.OCEndpoint;
import org.iotivity.OCEndpointUtil;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCQos;
import org.iotivity.OCResourcePropertiesMask;
import org.iotivity.oc.OcUtils;

import java.util.Arrays;

public class MyDiscoveryHandler implements OCDiscoveryHandler {

    private static final String TAG = MyDiscoveryHandler.class.getSimpleName();

    private ClientActivity activity;
    private Light light;

    public MyDiscoveryHandler(ClientActivity activity) {
        this.activity = activity;
    }

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoint, int resourcePropertiesMask) {
        activity.msg("DiscoveryHandler:");
        activity.msg("\tanchor: " + anchor);
        activity.msg("\turi: " + uri);
        activity.msg("\ttypes: " + Arrays.toString(types));

        String interfacesFound = "";
        if ((interfaceMask & OCInterfaceMask.S) > 0) {
            interfacesFound += "S";
        }
        if ((interfaceMask & OCInterfaceMask.A) > 0) {
            if (!interfacesFound.isEmpty()) {
                interfacesFound += " | ";
            }
            interfacesFound += "A";
        }
        if ((interfaceMask & OCInterfaceMask.RW) > 0) {
            if (!interfacesFound.isEmpty()) {
                interfacesFound += " | ";
            }
            interfacesFound += "RW";
        }
        if ((interfaceMask & OCInterfaceMask.R) > 0) {
            if (!interfacesFound.isEmpty()) {
                interfacesFound += " | ";
            }
            interfacesFound += "R";
        }
        if ((interfaceMask & OCInterfaceMask.B) > 0) {
            if (!interfacesFound.isEmpty()) {
                interfacesFound += " | ";
            }
            interfacesFound += "B";
        }
        if ((interfaceMask & OCInterfaceMask.LL) > 0) {
            if (!interfacesFound.isEmpty()) {
                interfacesFound += " | ";
            }
            interfacesFound += "LL";
        }
        if ((interfaceMask & OCInterfaceMask.BASELINE) > 0) {
            if (!interfacesFound.isEmpty()) {
                interfacesFound += " | ";
            }
            interfacesFound += "BASELINE";
        }
        activity.msg("\tinterfaces: " + interfacesFound);

        String propertiesFound = "";
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_PERIODIC) > 0) {
            propertiesFound += "PERIODIC";
        }
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_SECURE) > 0) {
            if (!propertiesFound.isEmpty()) {
                propertiesFound += " | ";
            }
            propertiesFound += "SECURE";
        }
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_OBSERVABLE) > 0) {
            if (!propertiesFound.isEmpty()) {
                propertiesFound += " | ";
            }
            propertiesFound += "OBSERVABLE";
        }
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_DISCOVERABLE) > 0) {
            if (!propertiesFound.isEmpty()) {
                propertiesFound += " | ";
            }
            propertiesFound += "DISCOVERABLE";
        }
        activity.msg("\tresource properties: " + propertiesFound);

        for (String type : types) {
            if (type.equals("oic.r.switch.binary")) {
                light = new Light();
                light.serverEndpoint = OCEndpointUtil.listCopy(endpoint);
                light.serverUri = uri;
                activity.msg("\tResource " + light.serverUri + " hosted at endpoint(s):");
                OCEndpoint ep = endpoint;
                while (ep != null) {
                    String endpointStr = OcUtils.endpointToString(ep);
                    activity.msg("\t\tendpoint: " + endpointStr);
                    activity.msg("\t\t\tendpoint.device " + ep.getDevice());
                    activity.msg("\t\t\tendpoint.flags " + ep.getFlags());
                    activity.msg("\t\t\tendpoint.interfaceIndex " + ep.getInterfaceIndex());
                    activity.msg("\t\t\tendpoint.version " + ep.getVersion().toString());
                    ep = ep.getNext();
                }
                activity.printLine();
                GetLightResponseHandler responseHandler = new GetLightResponseHandler(activity, light);
                OcUtils.doGet(light.serverUri, light.serverEndpoint, null, responseHandler, OCQos.LOW_QOS);
                return OCDiscoveryFlags.OC_STOP_DISCOVERY;
            }
        }
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}
