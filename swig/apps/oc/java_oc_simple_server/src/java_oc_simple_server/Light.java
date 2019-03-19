package java_oc_simple_server;

public class Light {

    private String name;
    private int power;
    private boolean state;

    public Light(String name) {
        this(name, 0, false);
    }

    public Light(String name, int power, boolean state) {
        this.name = name;
        setPower(power);
        setState(state);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getPower() {
        return power;
    }

    public void setPower(int power) {
        this.power = power;
    }

    public boolean getState() {
        return state;
    }

    public void setState(boolean state) {
        this.state = state;
    }
}
