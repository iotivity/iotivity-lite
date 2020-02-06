package org.iotivity.multideviceclient;

import android.util.Log;

import org.iotivity.OCEndpoint;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCResourcePropertiesMask;
import org.iotivity.oc.OcRemoteResource;
import org.iotivity.oc.OcUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class ResourceDetailsHelper {

    private static final String TAG = ResourceDetailsHelper.class.getSimpleName();

    static public void buildResourceDetails(OcRemoteResource resource, ArrayList<HashMap<String, String>> resourceDetailsList) {
        if (resource != null) {
            HashMap<String, String> item = new HashMap<>();

            String line = "Types: " + Arrays.toString(resource.getTypes());
            item.put("line1", line);
            Log.d(TAG, line);

            StringBuilder interfaces = new StringBuilder();
            if ((resource.getInterfaceMask() & OCInterfaceMask.BASELINE) > 0) {
                interfaces.append("BASELINE");
            }
            if ((resource.getInterfaceMask() & OCInterfaceMask.LL) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("LL");
            }
            if ((resource.getInterfaceMask() & OCInterfaceMask.B) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("B");
            }
            if ((resource.getInterfaceMask() & OCInterfaceMask.R) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("R");
            }
            if ((resource.getInterfaceMask() & OCInterfaceMask.RW) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("RW");
            }
            if ((resource.getInterfaceMask() & OCInterfaceMask.A) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("A");
            }
            if ((resource.getInterfaceMask() & OCInterfaceMask.S) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("S");
            }
            if ((resource.getInterfaceMask() & OCInterfaceMask.CREATE) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("CREATE");
            }
            line = "Interfaces: " + interfaces.toString();
            item.put("line2", line);
            Log.d(TAG, line);

            StringBuilder resourceProperties = new StringBuilder();
            if ((resource.getResourcePropertiesMask() & OCResourcePropertiesMask.OC_DISCOVERABLE) > 0) {
                resourceProperties.append("DISCOVERABLE");
            }
            if ((resource.getResourcePropertiesMask() & OCResourcePropertiesMask.OC_OBSERVABLE) > 0) {
                if (resourceProperties.length() > 0) {
                    resourceProperties.append(" | ");
                }
                resourceProperties.append("OBSERVABLE");
            }
            if ((resource.getResourcePropertiesMask() & OCResourcePropertiesMask.OC_SECURE) > 0) {
                if (resourceProperties.length() > 0) {
                    resourceProperties.append(" | ");
                }
                resourceProperties.append("SECURE");
            }
            if ((resource.getResourcePropertiesMask() & OCResourcePropertiesMask.OC_PERIODIC) > 0) {
                if (resourceProperties.length() > 0) {
                    resourceProperties.append(" | ");
                }
                resourceProperties.append("PERIODIC");
            }
            line = "Resource Properties: " + resourceProperties.toString();
            item.put("line3", line);
            Log.d(TAG, line);

            StringBuilder endPoints = new StringBuilder();
            for (OCEndpoint endpoint : resource.getEndpoints()) {
                if (endPoints.length() > 0) {
                    endPoints.append("\n");
                }
                endPoints.append("\t" + OcUtils.endpointToString(endpoint));
            }
            line = "Endpoints:\n" + endPoints.toString();
            item.put("line4", line);
            Log.d(TAG, line);

            resourceDetailsList.add(item);
        }
    }
}
