package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcCborException;
import org.iotivity.oc.OcRepresentation;
import org.iotivity.oc.OcUtils;

import java.lang.reflect.Array;
import java.util.Arrays;

public class PostTelevisionRequestHandler implements OCRequestHandler {

    private static final String TAG = PostTelevisionRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Television television;

    public PostTelevisionRequestHandler(ServerActivity activity, Television television) {
        this.activity = activity;
        this.television = television;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Post Television Request Handler");

        activity.msg("Post Television:");

        OcRepresentation rep = new OcRepresentation(request.getRequestPayload());
        if (Television.MEDIA_LIST_KEY.equalsIgnoreCase(rep.getKey())) {
            try {
                OcRepresentation mediaList = rep.getObjectArray(Television.MEDIA_LIST_KEY);
                activity.msg("\t" + Television.MEDIA_LIST_KEY + ":");

                while (mediaList != null) {
                    OcRepresentation mediaObject = mediaList.getObject();
                    Media media = Media.createFromOcRepresentation(mediaObject);
                    television.addMedia(media);

                    activity.msg("\t\t" + Media.URL_KEY + ": " + media.getUrl());
                    activity.msg("\t\t" + Media.SDP_KEY + ": " + Arrays.toString(media.getSdp()));

                    mediaList = mediaList.getNext();
                }

            } catch (OcCborException e) {
                // ignore -- no media list
            }

            activity.printLine();
            OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
        }
    }
}
