package org.iotivity.simpleserver;

import android.util.Log;

import org.iotivity.CborEncoder;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;

public class GetLightRequestHandler implements OCRequestHandler {

    private static final String TAG = GetLightRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Light light;

    public GetLightRequestHandler(ServerActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Get Light Request Handler");

        activity.msg("Get Light:");

        ++light.power; // auto increment

        activity.msg("\t" + light.name + ", " + light.power + ", " + light.state);
        activity.printLine();

        CborEncoder root = OCMain.repBeginRootObject();
        switch (interfaces) {
            case OCInterfaceMask.BASELINE: {
                OCMain.processBaselineInterface(request.getResource());
                break;
            }
            case OCInterfaceMask.RW: {
                OCMain.repSetBoolean(root, "state", light.state);
                OCMain.repSetLong(root, "power", light.power);
                OCMain.repSetTextString(root, "name", light.name);
                break;
            }
            default:
                break;
        }
        OCMain.repEndRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}
