package java_oc_simple_media_server;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MediaController {

    private String name;
    private boolean playState; // true if playing
    private String currentAction;
    private List<String> allowedActions; // future actions from current action
    private Number speed; // integer or double
    private String location; // integer index or time

    static final private List<String> allAllowedActions = new ArrayList<>();

    static {
        allAllowedActions.add("stop");
        allAllowedActions.add("play");
        allAllowedActions.add("pause");
        allAllowedActions.add("fastforward");
        allAllowedActions.add("rewind");
        allAllowedActions.add("stepforward");
        allAllowedActions.add("stepbackward");
        allAllowedActions.add("seek");
    }

    public MediaController(String name) {
        setName(name);
        setCurrentAction(allAllowedActions.get(0));
        String[] allowedActions = { allAllowedActions.get(1) };
        setAllowedActions(allowedActions);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = (name != null) ? name : "";
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
        if (currentAction.equalsIgnoreCase(allAllowedActions.get(0))
                || currentAction.equalsIgnoreCase(allAllowedActions.get(2))) {
            // stop or pause
            setPlayState(false);
            // TODO set speed to zero

            if (currentAction.equalsIgnoreCase(allAllowedActions.get(0))) {
                // stop
                // TODO set location to zero

                String[] allowedActions = { allAllowedActions.get(1) };
                setAllowedActions(allowedActions);
            }

            if (currentAction.equalsIgnoreCase(allAllowedActions.get(2))) {
                // pause

                String[] allowedActions = { allAllowedActions.get(1), allAllowedActions.get(0) };
                setAllowedActions(allowedActions);
            }
        }

        if (currentAction.equalsIgnoreCase(allAllowedActions.get(1))) {
            // play
            String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(2) };
            setAllowedActions(allowedActions);
            setPlayState(true);
        }
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
}
