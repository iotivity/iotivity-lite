package org.iotivity.simpleclient;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.OCRep;
import org.iotivity.OCResponseHandler;

public class PostLightResponseHandler implements OCResponseHandler {

    private static final String TAG = PostLightResponseHandler.class.getSimpleName();

    private ClientActivity activity;
    private Light light;

    public PostLightResponseHandler(ClientActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        activity.msg("POST light:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            activity.msg("\tPOST response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            activity.msg("\tPOST response: CREATED");
        } else {
            activity.msg("\tPOST response code " + response.getCode().toString() + " (" + response.getCode() + ")");
        }
        activity.printLine();

        Post2LightResponseHandler postLight = new Post2LightResponseHandler(activity, light);
        if (OCMain.initPost(light.serverUri, light.serverEndpoint, null, postLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setBoolean(root, "state", true);
            OCRep.setLong(root, "power", 55);
            OCRep.endRootObject();

            if (OCMain.doPost()) {
                activity.msg("\tSent POST2 request");
            } else {
                activity.msg("\tCould not send POST2 request");
            }
        } else {
            activity.msg("\tCould not init POST2 request");
        }
        activity.printLine();
    }
}
