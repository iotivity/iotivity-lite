package java_oc_simple_media_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetMediaControlResourceResponseHandler implements OCResponseHandler {

    private MediaControlResource mediaControlResource;

    public GetMediaControlResourceResponseHandler(MediaControlResource mediaControlResource) {
        this.mediaControlResource = mediaControlResource;
    }

    @Override
    public void handler(OCClientResponse response) {
        OCRepresentation rep = response.getPayload();
        while (rep != null) {
            switch (rep.getType()) {
            case OC_REP_BOOL:
                if ("playstate".equalsIgnoreCase(rep.getName())) {
                    mediaControlResource.setPlayState(rep.getValue().getBool());
                }
                break;
            case OC_REP_INT:
                break;
            case OC_REP_STRING:
                if ("name".equalsIgnoreCase(rep.getName())) {
                    mediaControlResource.setName(rep.getValue().getString());
                }
                if ("mediaaction".equalsIgnoreCase(rep.getName())) {
                    mediaControlResource.setCurrentAction(rep.getValue().getString());
                }
                break;
            case OC_REP_STRING_ARRAY:
                if ("mediaactions".equalsIgnoreCase(rep.getName())) {
                    mediaControlResource.setAllowedActions(OCRep.ocArrayToStringArray(rep.getValue().getArray()));
                }
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }
    }
}
