package java_oc_simple_media_client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class MediaControlResource extends OcfServerResource {

    private boolean playState;
    private String currentAction;
    private List<String> allowedActions;
    private double[] fastforwardAllowedValues;
    private double[] rewindAllowedValues;
    private double[] stepForwardRange;
    private double[] stepBackwardRange;
    private double[] seekRange;
    private Double step;
    private double speed;
    private double location;
    private String mediaControlUriExp;

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
        return (allowedActions != null) ? allowedActions.toArray(new String[0]) : new String[0];
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

    public double[] getFastforwardAllowedValues() {
        return fastforwardAllowedValues;
    }

    public void setFastforwardAllowedValues(double[] allowedValues) {
        fastforwardAllowedValues = allowedValues;
    }

    public double[] getRewindAllowedValues() {
        return rewindAllowedValues;
    }

    public void setRewindAllowedValues(double[] allowedValues) {
        rewindAllowedValues = allowedValues;
    }

    public double[] getStepForwardRange() {
        return stepForwardRange;
    }

    public void setStepForwardRange(double[] range) {
        stepForwardRange = range;
    }

    public double[] getStepBackwardRange() {
        return stepBackwardRange;
    }

    public void setStepBackwardRange(double[] range) {
        stepBackwardRange = range;
    }

    public double[] getSeekRange() {
        return seekRange;
    }

    public void setSeekRange(double[] range) {
        seekRange = range;
    }

    public Double getStep() {
        return step;
    }

    public void setStep(Double step) {
        step = step;
    }

    public double getSpeed() {
        return speed;
    }

    public void setSpeed(double speed) {
        this.speed = speed;
    }

    public double getLocation() {
        return location;
    }

    public void setLocation(double location) {
        this.location = location;
    }

    public String getMediaControlUriExp() {
        return mediaControlUriExp;
    }

    public void setMediaControlUriExp(String uriExp) {
        mediaControlUriExp = uriExp;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{ ");
        sb.append("{\"name\", " + getName() + "}, ");
        sb.append("{\"uri\", " + getServerUri() + "}, ");
        sb.append("{\"playstate\", " + getPlayState() + "}, ");
        sb.append("{\"mediaaction\", " + getCurrentAction() + "}, ");
        sb.append("{\"mediaactions\", " + Arrays.toString(getAllowedActions()) + "}, ");
        sb.append("{\"speed\", " + getSpeed() + "}, ");
        sb.append("{\"location\", " + getLocation() + "}");
        sb.append(" }");
        return sb.toString();
    }
}
