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
        boolean startTimerTask = false;

        if (action.equalsIgnoreCase(allAllowedActions.get(3))) {
            // fastforward
            String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(1), allAllowedActions.get(2),
                    allAllowedActions.get(3), allAllowedActions.get(4) };
            setAllowedActions(allowedActions);
            if (currentAction.equalsIgnoreCase(action)) {
                // already doing fastforward
                setSpeed(getSpeed() + 1.0);
            } else {
                setSpeed(2.0);
            }
            startTimerTask = true;
        }

        if (action.equalsIgnoreCase(allAllowedActions.get(4))) {
            // rewind
            String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(1), allAllowedActions.get(2),
                    allAllowedActions.get(3), allAllowedActions.get(4) };
            setAllowedActions(allowedActions);
            if (currentAction.equalsIgnoreCase(action)) {
                // already doing rewind
                setSpeed(getSpeed() - 1.0);
            } else {
                setSpeed(-2.0);
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
                String[] allowedActions = { allAllowedActions.get(1) };
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

        if (timer != null) {
            timer.cancel();
            timer = null;
        }

        if ((primaryStage != null) && (primaryStage.getUserData() != null)) {
            MediaPlayer mediaPlayer = (MediaPlayer) primaryStage.getUserData();
            if (mediaPlayer != null) {
                // prune allowed actions for java fx media player
                if (currentAction.equalsIgnoreCase(allAllowedActions.get(2))) {
                    // pause
                    String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(1),
                            allAllowedActions.get(3) };
                    setAllowedActions(allowedActions);
                }
                if (currentAction.equalsIgnoreCase(allAllowedActions.get(1))
                        || currentAction.equalsIgnoreCase(allAllowedActions.get(3))) {
                    // play or fastforward
                    String[] allowedActions = { allAllowedActions.get(0), allAllowedActions.get(2),
                            allAllowedActions.get(3) };
                    setAllowedActions(allowedActions);
                    setPlayState(true);
                }

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
                                mediaPlayer.setRate(getSpeed());
                                mediaPlayer.play();
                            } else {
                                System.out.println("Ignoring request " + currentAction);
                            }
                        } catch (Exception e) {
                            System.err.println("Error " + e);
                        }
                    }
                });
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
        this.speed = speed;
    }

    public double getLocation() {
        return location;
    }

    public void setLocation(double location) {
        this.location = Math.max(location, 0.0);
    }
}
