package org.iotivity.multideviceserver;

public class Thermostat {

    static public final String TEMPERATURE_KEY = "temperature";

    private String name;
    private double temperature;

    public Thermostat(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public double getTemperature() {
        return temperature;
    }

    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }
}
