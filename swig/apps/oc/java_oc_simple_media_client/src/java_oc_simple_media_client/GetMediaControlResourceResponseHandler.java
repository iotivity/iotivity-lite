package java_oc_simple_media_client;

import java.util.ArrayList;
import java.util.List;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetMediaControlResourceResponseHandler implements OCResponseHandler {

    private static final String NAME_KEY = "name";
    private static final String PLAYSTATE_KEY = "playstate";
    private static final String MEDIA_SPEED_KEY = "mediaspeed";
    private static final String MEDIA_LOCATION_KEY = "medialocation";
    private static final String MEDIA_ACTION_KEY = "mediaaction";
    private static final String MEDIA_ACTIONS_KEY = "mediaactions";
    private static final String ALLOWED_VALUES_KEY = "allowedvalues";
    private static final String RANGE_KEY = "range";
    private static final String STEP_KEY = "step";

    private static final String FASTFORWARD_ACTION = "fastforward";
    private static final String REWIND_ACTION = "rewind";
    private static final String STEPFORWARD_ACTION = "stepforward";
    private static final String STEPBACKWARD_ACTION = "stepbackward";
    private static final String SEEK_ACTION = "seek";

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
                        List<String> mediaActionsList = new ArrayList<>();
                        OcRepresentation mediaActionsArray = rep.getObjectArray(MEDIA_ACTIONS_KEY);
                        while (mediaActionsArray != null) {
                            OcRepresentation mediaActionObject = mediaActionsArray.getObject();
                            if (MEDIA_ACTION_KEY.equalsIgnoreCase(mediaActionObject.getKey())) {
                                String mediaAction = mediaActionObject.getString(MEDIA_ACTION_KEY);
                                mediaActionsList.add(mediaAction);
                                if (mediaAction.equalsIgnoreCase(FASTFORWARD_ACTION)) {
                                    try {
                                        double[] allowedValues = mediaActionObject.getDoubleArray(ALLOWED_VALUES_KEY);
                                        mediaControlResource.setFastforwardAllowedValues(allowedValues);
                                    } catch (OcCborException oce) {
                                        // ignore if allowed values not found
                                    }
                                }
                                if (mediaAction.equalsIgnoreCase(REWIND_ACTION)) {
                                    try {
                                        double[] allowedValues = mediaActionObject.getDoubleArray(ALLOWED_VALUES_KEY);
                                        mediaControlResource.setRewindAllowedValues(allowedValues);
                                    } catch (OcCborException oce) {
                                        // ignore if allowed values not found
                                    }
                                }
                                if (mediaAction.equalsIgnoreCase(STEPFORWARD_ACTION)) {
                                    try {
                                        double[] range = mediaActionObject.getDoubleArray(RANGE_KEY);
                                        mediaControlResource.setStepForwardRange(range);
                                    } catch (OcCborException oce) {
                                        // ignore if range not found
                                    }
                                    try {
                                        double step = mediaActionObject.getDouble(STEP_KEY);
                                        mediaControlResource.setStep(step);
                                    } catch (OcCborException oce) {
                                        // ignore if step not found
                                    }
                                }
                                if (mediaAction.equalsIgnoreCase(STEPBACKWARD_ACTION)) {
                                    try {
                                        double[] range = mediaActionObject.getDoubleArray(RANGE_KEY);
                                        mediaControlResource.setStepBackwardRange(range);
                                    } catch (OcCborException oce) {
                                        // ignore if range not found
                                    }
                                    try {
                                        double step = mediaActionObject.getDouble(STEP_KEY);
                                        mediaControlResource.setStep(step);
                                    } catch (OcCborException oce) {
                                        // ignore if step not found
                                    }
                                }
                                if (mediaAction.equalsIgnoreCase(SEEK_ACTION)) {
                                    try {
                                        double[] range = mediaActionObject.getDoubleArray(RANGE_KEY);
                                        mediaControlResource.setSeekRange(range);
                                    } catch (OcCborException oce) {
                                        // ignore if range not found
                                    }
                                }
                            }
                            mediaActionsArray = mediaActionsArray.getNext();
                        }
                        mediaControlResource.setAllowedActions(mediaActionsList.toArray(new String[0]));
                    }
                } catch (OcCborException e) {
                    System.err.println(e.getMessage());
                }

                rep = rep.getNext();
            }
        }
    }
}
