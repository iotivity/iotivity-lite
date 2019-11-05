package org.iotivity.multideviceclient;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCResourcePropertiesMask;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class ResourceDetailsHelper {

    private static final String TAG = ResourceDetailsHelper.class.getSimpleName();

    static public void buildResourceDetails(OcfResourceInfo resourceInfo, ArrayList<HashMap<String, String>> resourceDetailsList) {
        if (resourceInfo != null) {
            HashMap<String, String> item = new HashMap<>();

            String line = "Types: " + Arrays.toString(resourceInfo.getTypes());
            item.put("line1", line);
            Log.d(TAG, line);

            StringBuilder interfaces = new StringBuilder();
            if ((resourceInfo.getInterfaceMask() & OCInterfaceMask.BASELINE) > 0) {
                interfaces.append("BASELINE");
            }
            if ((resourceInfo.getInterfaceMask() & OCInterfaceMask.LL) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("LL");
            }
            if ((resourceInfo.getInterfaceMask() & OCInterfaceMask.B) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("B");
            }
            if ((resourceInfo.getInterfaceMask() & OCInterfaceMask.R) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("R");
            }
            if ((resourceInfo.getInterfaceMask() & OCInterfaceMask.RW) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("RW");
            }
            if ((resourceInfo.getInterfaceMask() & OCInterfaceMask.A) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("A");
            }
            if ((resourceInfo.getInterfaceMask() & OCInterfaceMask.S) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("S");
            }
            if ((resourceInfo.getInterfaceMask() & OCInterfaceMask.CREATE) > 0) {
                if (interfaces.length() > 0) {
                    interfaces.append(" | ");
                }
                interfaces.append("CREATE");
            }
            line = "Interfaces: " + interfaces.toString();
            item.put("line2", line);
            Log.d(TAG, line);

            StringBuilder resourceProperties = new StringBuilder();
            if ((resourceInfo.getResourcePropertiesMask() & OCResourcePropertiesMask.OC_DISCOVERABLE) > 0) {
                resourceProperties.append("DISCOVERABLE");
            }
            if ((resourceInfo.getResourcePropertiesMask() & OCResourcePropertiesMask.OC_OBSERVABLE) > 0) {
                if (resourceProperties.length() > 0) {
                    resourceProperties.append(" | ");
                }
                resourceProperties.append("OBSERVABLE");
            }
            if ((resourceInfo.getResourcePropertiesMask() & OCResourcePropertiesMask.OC_SECURE) > 0) {
                if (resourceProperties.length() > 0) {
                    resourceProperties.append(" | ");
                }
                resourceProperties.append("SECURE");
            }
            if ((resourceInfo.getResourcePropertiesMask() & OCResourcePropertiesMask.OC_PERIODIC) > 0) {
                if (resourceProperties.length() > 0) {
                    resourceProperties.append(" | ");
                }
                resourceProperties.append("PERIODIC");
            }
            line = "Resource Properties: " + resourceProperties.toString();
            item.put("line3", line);
            Log.d(TAG, line);

            StringBuilder endPoints = new StringBuilder();
            for (String endpoint : resourceInfo.getEndpoints()) {
                if (endPoints.length() > 0) {
                    endPoints.append("\n");
                }
                endPoints.append("\t" + endpoint);
            }
            line = "Endpoints:\n" + endPoints.toString();
            item.put("line4", line);
            Log.d(TAG, line);

            resourceDetailsList.add(item);
        }
    }
}
