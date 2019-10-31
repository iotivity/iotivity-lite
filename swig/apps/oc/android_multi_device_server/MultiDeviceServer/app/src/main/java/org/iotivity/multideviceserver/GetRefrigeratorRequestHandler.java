package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcCborEncoder;
import org.iotivity.oc.OcUtils;

public class GetRefrigeratorRequestHandler implements OCRequestHandler {

    private static final String TAG = GetRefrigeratorRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Refrigerator refrigerator;

    public GetRefrigeratorRequestHandler(ServerActivity activity, Refrigerator refrigerator) {
        this.activity = activity;
        this.refrigerator = refrigerator;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Get Refrigerator Request Handler");

        activity.msg("Get Refrigerator:");
        activity.msg("\t" + refrigerator.getName() + ", " + refrigerator.getFilter() + ", " +
                refrigerator.isRapidFreeze() + ", " + refrigerator.isRapidCool() + ", " +
                refrigerator.isDefrost());
        activity.printLine();

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
            case OCInterfaceMask.BASELINE: {
                root.processBaselineInterface(request.getResource());
                break;
            }
            case OCInterfaceMask.A: {
                root.setLong(Refrigerator.FILTER_KEY, refrigerator.getFilter());
                root.setBoolean(Refrigerator.RAPID_FREEZE_KEY, refrigerator.isRapidFreeze());
                root.setBoolean(Refrigerator.RAPID_COOL_KEY, refrigerator.isRapidCool());
                root.setBoolean(Refrigerator.DEFROST_KEY, refrigerator.isDefrost());
                break;
            }
            default:
                break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}
