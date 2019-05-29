package java_oc_simple_media_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetMediaControlResourceResponseHandler implements OCResponseHandler {

    private static final String NAME_KEY = "name";
    private static final String PLAYSTATE_KEY = "playstate";
    private static final String MEDIA_SPEED_KEY = "mediaspeed";
    private static final String MEDIA_LOCATION_KEY = "medialocation";
    private static final String MEDIA_ACTION_KEY = "mediaaction";
    private static final String MEDIA_ACTIONS_KEY = "mediaactions";

    private MediaControlResource mediaControlResource;

    public GetMediaControlResourceResponseHandler(MediaControlResource mediaControlResource) {
        this.mediaControlResource = mediaControlResource;
    }

    @Override
    public void handler(OCClientResponse response) {

        if (response.getPayload() != null) {
            OcRepresentation rep = new OcRepresentation(response.getPayload());
            while (rep != null) {
                try {
                    if (NAME_KEY.equalsIgnoreCase(rep.getKey())) {
                        mediaControlResource.setName(rep.getString(NAME_KEY));
                    }
                    if (PLAYSTATE_KEY.equalsIgnoreCase(rep.getKey())) {
                        mediaControlResource.setPlayState(rep.getBoolean(PLAYSTATE_KEY));
                    }
                    if (MEDIA_SPEED_KEY.equalsIgnoreCase(rep.getKey())) {
                        mediaControlResource.setSpeed(rep.getDouble(MEDIA_SPEED_KEY));
                    }
                    if (MEDIA_LOCATION_KEY.equalsIgnoreCase(rep.getKey())) {
                        mediaControlResource.setLocation(rep.getDouble(MEDIA_LOCATION_KEY));
                    }
                    if (MEDIA_ACTION_KEY.equalsIgnoreCase(rep.getKey())) {
                        mediaControlResource.setCurrentAction(rep.getString(MEDIA_ACTION_KEY));
                    }
                    if (MEDIA_ACTIONS_KEY.equalsIgnoreCase(rep.getKey())) {
                        mediaControlResource.setAllowedActions(rep.getStringArray(MEDIA_ACTIONS_KEY));
                    }
                } catch (OcCborException e) {
                    System.err.println(e.getMessage());
                }

                rep = rep.getNext();
            }
        }
    }
}
