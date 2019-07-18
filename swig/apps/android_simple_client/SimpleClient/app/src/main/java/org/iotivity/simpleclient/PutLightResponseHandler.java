package org.iotivity.simpleclient;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.OCRep;
import org.iotivity.OCResponseHandler;

public class PutLightResponseHandler implements OCResponseHandler {

    private static final String TAG = PutLightResponseHandler.class.getSimpleName();

    private ClientActivity activity;
    private Light light;

    public PutLightResponseHandler(ClientActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        activity.msg("PUT light:");
        try {
            if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
                activity.msg("\tPUT response: CHANGED");
            } else {
                activity.msg("\tPUT response code " + response.getCode().toString() + " (" + response.getCode() + ")");
            }
        } catch (IllegalArgumentException e) {
            activity.msg("\tError: Bad Response Code, Client not properly provisioned");
        }
        activity.printLine();

        PostLightResponseHandler postLight = new PostLightResponseHandler(activity, light);
        if (OCMain.initPost(light.serverUri, light.serverEndpoint, null, postLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setBoolean(root, "state", false);
            OCRep.setLong(root, "power", 105);
            OCRep.endRootObject();

            if (OCMain.doPost()) {
                activity.msg("\tSent POST request");
            } else {
                activity.msg("\tCould not send POST request");
            }
        } else {
            activity.msg("\tCould not init POST request");
        }
        activity.printLine();
    }
}
