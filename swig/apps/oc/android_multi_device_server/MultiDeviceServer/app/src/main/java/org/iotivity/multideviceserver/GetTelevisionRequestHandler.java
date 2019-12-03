package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcCborEncoder;
import org.iotivity.oc.OcUtils;

import java.util.Arrays;

public class GetTelevisionRequestHandler implements OCRequestHandler {

    private static final String TAG = GetTelevisionRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Television television;

    public GetTelevisionRequestHandler(ServerActivity activity, Television television) {
        this.activity = activity;
        this.television = television;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Get Television Request Handler");

        activity.msg("Get Television:");
        activity.msg("\t" + television.getName());

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
            case OCInterfaceMask.BASELINE: {
                root.processBaselineInterface(request.getResource());
                break;
            }
            case OCInterfaceMask.RW: {
                OcCborEncoder mediaList = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY, root, "media");
                for (Media media : television.getMediaList()) {
                    OcCborEncoder mediaObject = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY_ITEM, mediaList);
                    mediaObject.setTextString(Media.URL_KEY, media.getUrl());
                    mediaObject.setStringArray(Media.SDP_KEY, media.getSdp());
                    mediaObject.done();
                    activity.msg("\t\t" + media.getUrl() + ", " + Arrays.toString(media.getSdp()));
                }
                mediaList.done();
                break;
            }
            default:
                break;
        }
        root.done();
        activity.printLine();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}
