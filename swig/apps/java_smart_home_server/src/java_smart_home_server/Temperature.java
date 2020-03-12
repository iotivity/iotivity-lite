package java_smart_home_server;

public class Temperature {
    
    static public final String TEMPERATURE_KEY = "temperature";
    static public final String UNITS_KEY = "units";
    static public final String RANGE_KEY = "range";

    static private final double MIN_F = 32.0;
    static private final double MAX_F = 212.0;
    static private final double MIN_C = 0.0;
    static private final double MAX_C = 100.0;
    static private final double MIN_K = 273.15;
    static private final double MAX_K = 373.15;

    public enum Units {
        F, C, K
    }
    
    static public double getMin(Units units) {
        switch (units) {
        case F:
            return MIN_F;
        case C:
            return MIN_C;
        case K:
            return MIN_K;
        default:
            return -1.0;
        }
    }

    static public double getMax(Units units) {
        switch (units) {
        case F:
            return MAX_F;
        case C:
            return MAX_C;
        case K:
            return MAX_K;
        default:
            return -1.0;
        }
    }

    private double temperature;
    private Units units;

    public Temperature() {
        this(-1.0, Units.F);
    }

    public Temperature(double temperature, Units units) {
        setTemperature(temperature);
        setUnits(units);
    }

    public double getTemperature() {
        return temperature;
    }

    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }

    public Units getUnits() {
        return units;
    }

    public void setUnits(Units units) {
        this.units = units;
    }

    public double getTemperatureAsF() {
        switch (units) {
        case F:
            return temperature;
        case C:
            return (temperature * 9 / 5) + 32;
        case K:
            return ((temperature - 273.15) * 9 / 5) + 32;
        default:
            return -1.0;
        }
    }

    public double getTemperatureAsC() {
        switch (units) {
        case F:
            return (temperature - 32) * 5 / 9;
        case C:
            return temperature;
        case K:
            return temperature - 273.15;
        default:
            return -1.0;
        }
    }

    public double getTemperatureAsK() {
        switch (units) {
        case F:
            return ((temperature - 32) * 5 / 9) + 273.15;
        case C:
            return temperature + 273.15;
        case K:
            return temperature;
        default:
            return -1.0;
        }
    }

    public double getMin() {
        return getMin(units);
    }

    public double getMax() {
        return getMax(units);
    }

    public boolean isInRange() {
        return ((temperature >= getMin()) && (temperature <= getMax()));
    }
}
