package java_oc_simple_server;

public class Light {

    private String name;
    private long power;
    private boolean state;

    public Light(String name) {
        this(name, 0, false);
    }

    public Light(String name, int power, boolean state) {
        setName(name);
        setPower(power);
        setState(state);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getPower() {
        return power;
    }

    public void setPower(long power) {
        this.power = power;
    }

    public boolean getState() {
        return state;
    }

    public void setState(boolean state) {
        this.state = state;
    }
}
