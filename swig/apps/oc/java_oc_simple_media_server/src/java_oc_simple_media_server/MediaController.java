package java_oc_simple_media_server;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javafx.application.Platform;
import javafx.scene.media.MediaPlayer;
import javafx.stage.Stage;
import javafx.util.Duration;

public class MediaController {

    private String name;
    private boolean playState; // true if playing
    private String currentAction;
    private List<String> allowedActions; // future actions from current action
    private double speed;
    private double location;
    private Timer timer;
    private Stage primaryStage;

    static final private List<String> allAllowedActions = new ArrayList<>();

    static final private double[] fastforwardAllowedValues = new double[] { 0.1, 0.2, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0,
            5.0, 6.0, 7.0, 8.0 };
    static final private double[] rewindAllowedValues = new double[] { -1.0, -2.0, -4.0 };
    static final private double[] stepForwardRange = new double[] { 0.0, 30000.0 };
    static final private double[] stepBackwardRange = new double[] { 0.0, -30000.0 };
    static final private double[] seekRange = new double[] { 0.0, 60000.0 };
    static final private double step = 1000.0;

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

    public MediaController(String name, Stage primaryStage) {
        setName(name);
        this.primaryStage = primaryStage;
        setCurrentAction(allAllowedActions.get(0), true);
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

    public void setCurrentAction(String action, boolean useDefaultSpeed) {
        boolean startTimerTask = false;

        if (action.equalsIgnoreCase(allAllowedActions.get(3))) {
            // fastforward
            String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(1), allAllowedActions.get(2),
                    allAllowedActions.get(3), allAllowedActions.get(4) };
            setAllowedActions(allowedActions);
            if (useDefaultSpeed) {
                if (currentAction.equalsIgnoreCase(action)) {
                    // already doing fastforward
                    setSpeed(getSpeed() + 1.0);
                } else {
                    setSpeed(2.0);
                }
            }
            startTimerTask = true;
        }

        if (action.equalsIgnoreCase(allAllowedActions.get(4))) {
            // rewind
            String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(1), allAllowedActions.get(2),
                    allAllowedActions.get(3), allAllowedActions.get(4) };
            setAllowedActions(allowedActions);
            if (useDefaultSpeed) {
                if (currentAction.equalsIgnoreCase(action)) {
                    // already doing rewind
                    setSpeed(getSpeed() - 1.0);
                } else {
                    setSpeed(-2.0);
                }
            }
            startTimerTask = true;
        }

        currentAction = action;

        if (currentAction.equalsIgnoreCase(allAllowedActions.get(0))
                || currentAction.equalsIgnoreCase(allAllowedActions.get(2))) {
            // stop or pause
            setPlayState(false);
            setSpeed(0.0);

            if (currentAction.equalsIgnoreCase(allAllowedActions.get(0))) {
                // stop
                setLocation(0.0);
                String[] allowedActions = { allAllowedActions.get(1), allAllowedActions.get(2),
                        allAllowedActions.get(3), allAllowedActions.get(5), allAllowedActions.get(7) };
                setAllowedActions(allowedActions);
            }

            if (currentAction.equalsIgnoreCase(allAllowedActions.get(2))) {
                // pause
                String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(1),
                        allAllowedActions.get(3), allAllowedActions.get(4), allAllowedActions.get(5),
                        allAllowedActions.get(6), allAllowedActions.get(7) };
                setAllowedActions(allowedActions);
            }
        }

        if (currentAction.equalsIgnoreCase(allAllowedActions.get(1))) {
            // play
            String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(2), allAllowedActions.get(3),
                    allAllowedActions.get(4) };
            setAllowedActions(allowedActions);
            setPlayState(true);
            setSpeed(1.0);
            startTimerTask = true;
        }

        if (currentAction.equalsIgnoreCase(allAllowedActions.get(5))
                || currentAction.equalsIgnoreCase(allAllowedActions.get(6))
                || currentAction.equalsIgnoreCase(allAllowedActions.get(7))) {
            // step forward or step backward or seek
            setPlayState(false);
            setSpeed(0.0);
            String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(1), allAllowedActions.get(3),
                    allAllowedActions.get(4), allAllowedActions.get(5), allAllowedActions.get(6),
                    allAllowedActions.get(7) };
            setAllowedActions(allowedActions);
        }

        if (timer != null) {
            timer.cancel();
            timer = null;
        }

        if ((primaryStage != null) && (primaryStage.getUserData() != null)) {
            MediaPlayer mediaPlayer = (MediaPlayer) primaryStage.getUserData();
            if (mediaPlayer != null) {
                Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            if (currentAction.equalsIgnoreCase(allAllowedActions.get(0))) {
                                // stop
                                mediaPlayer.seek(Duration.ZERO);
                                mediaPlayer.stop();
                            } else if (currentAction.equalsIgnoreCase(allAllowedActions.get(2))) {
                                // pause
                                mediaPlayer.pause();
                            } else if (currentAction.equalsIgnoreCase(allAllowedActions.get(1))
                                    || currentAction.equalsIgnoreCase(allAllowedActions.get(3))) {
                                // play or fastforward
                                mediaPlayer.seek(new Duration(getLocation()));
                                mediaPlayer.setRate(getSpeed());
                                mediaPlayer.play();
                            } else if (currentAction.equalsIgnoreCase(allAllowedActions.get(4))) {
                                // rewind
                                mediaPlayer.seek(new Duration(getLocation()));
                                mediaPlayer.pause();
                                // simulated below in timer task
                            } else if (currentAction.equalsIgnoreCase(allAllowedActions.get(5))
                                    || currentAction.equalsIgnoreCase(allAllowedActions.get(6))
                                    || currentAction.equalsIgnoreCase(allAllowedActions.get(7))) {
                                // step forward / step backward / seek
                                mediaPlayer.seek(new Duration(getLocation()));
                            } else {
                                System.out.println("Ignoring request " + currentAction);
                            }
                        } catch (Exception e) {
                            System.err.println("Error " + e);
                        }
                    }
                });
                if (startTimerTask) {
                    timer = new Timer(true);
                    timer.scheduleAtFixedRate(new TimerTask() {
                        @Override
                        public void run() {
                            if (currentAction.equalsIgnoreCase(allAllowedActions.get(4))) {
                                // rewind (simulated as seek to earlier)
                                mediaPlayer.seek(new Duration(getLocation() + (getSpeed() * 1000)));
                            }
                            setLocation(mediaPlayer.getCurrentTime().toMillis());
                        }
                    }, 0, 500);
                }
            }
        } else {
            if (startTimerTask) {
                if (getSpeed() < 0.0) {
                    System.out.print("<< ");
                } else if (getSpeed() > 1.0) {
                    System.out.print(">> ");
                } else {
                    System.out.print("> ");
                }
                timer = new Timer(true);
                timer.scheduleAtFixedRate(new TimerTask() {
                    @Override
                    public void run() {
                        setLocation(getLocation() + (getSpeed() * 50));
                        if (getLocation() > 0.0) {
                            for (int i = 0; i < Math.abs(getSpeed()); ++i) {
                                System.out.print(".");
                            }
                        }
                    }
                }, 0, 1000);
            }
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

    public double getSpeed() {
        return speed;
    }

    public void setSpeed(double speed) {
        this.speed = ((primaryStage != null) ? Math.min(speed, 8.0) : speed);
    }

    public double getLocation() {
        return location;
    }

    public void setLocation(double location) {
        this.location = Math.max(location, 0.0);
    }

    public double[] getFastforwardAllowedValues() {
        return ((primaryStage != null) ? fastforwardAllowedValues : null);
    }

    public double[] getRewindAllowedValues() {
        return ((primaryStage != null) ? rewindAllowedValues : null);
    }

    public double[] getStepForwardRange() {
        return ((primaryStage != null) ? stepForwardRange : null);
    }

    public double[] getStepBackwardRange() {
        return ((primaryStage != null) ? stepBackwardRange : null);
    }

    public double[] getSeekRange() {
        return ((primaryStage != null) ? seekRange : null);
    }

    public Double getStep() {
        return ((primaryStage != null) ? step : null);
    }
}
