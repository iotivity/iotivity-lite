package java_oc_simple_media_client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class MediaControlResource extends OcfServerResource {

    private boolean playState;
    private String currentAction;
    private List<String> allowedActions;
    private Number speed;
    private String location;
    private String mediaControlResUri;

    public MediaControlResource() {
    }

    public boolean getPlayState() {
        return playState;
    }

    public void setPlayState(boolean state) {
        playState = state;
    }

    public String getCurrentAction() {
        return currentAction;
    }

    public void setCurrentAction(String action) {
        currentAction = action;
    }

    public String[] getAllowedActions() {
        return allowedActions.toArray(new String[0]);
    }

    public void setAllowedActions(String[] actions) {
        if (actions != null) {
            if (allowedActions == null) {
                allowedActions = new ArrayList<>();
            }
            allowedActions.clear();
            Collections.addAll(allowedActions, actions);
        }
    }

    public String getMediaControlResUri() {
        return mediaControlResUri;
    }

    public void setMediaControlResUri(String uriExp) {
        mediaControlResUri = uriExp;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{ ");
        sb.append("{\"name\", " + getName() + "}, ");
        sb.append("{\"uri\", " + getServerUri() + "}, ");
        sb.append("{\"playstate\", " + getPlayState() + "}, ");
        sb.append("{\"mediaaction\", " + getCurrentAction() + "}, ");
        sb.append("{\"mediaactions\", " + Arrays.toString(getAllowedActions()) + "}, ");
        sb.append(" }");
        return sb.toString();
    }
}
