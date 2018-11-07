package org.iotivity.simpleclient;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.OCResponseHandler;

public class PostLightResponseHandler implements OCResponseHandler {

    private static final String TAG = PostLightResponseHandler.class.getSimpleName();

    private ClientActivity activity;

    public PostLightResponseHandler(ClientActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(OCClientResponse response) {
        Light light = (Light) response.getUser_data();
        activity.msg("POST light:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            activity.msg("\tPUT response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            activity.msg("\tPUT response: CREATED");
        } else {
            activity.msg("\tPUT response code " + response.getCode().toString() + "(" + response.getCode() + ")");
        }
        activity.printLine();

        Post2LightResponseHandler postLight = new Post2LightResponseHandler(activity);
        if (OCMain.initPost(light.serverUri, light.serverEndpoint, null, postLight, OCQos.LOW_QOS, light)) {
            CborEncoder root = OCMain.repBeginRootObject();
            OCMain.repSetBoolean(root, "state", true);
            OCMain.repSetInt(root, "power", 55);
            OCMain.repEndRootObject();

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
