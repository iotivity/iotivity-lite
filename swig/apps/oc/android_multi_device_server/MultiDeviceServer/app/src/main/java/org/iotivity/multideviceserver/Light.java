package org.iotivity.multideviceserver;

public class Light {

    static public final String SWITCH_KEY = "value";
    static public final String DIMMING_KEY = "dimmingSetting";

    private String name;
    private boolean on;
    private int dimming;

    public Light(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public boolean isOn() {
        return on;
    }

    public void setOn(boolean on) {
        this.on = on;
    }

    public int getDimming() {
        return dimming;
    }

    public void setDimming(int dimming) {
        this.dimming = dimming;
    }
}
