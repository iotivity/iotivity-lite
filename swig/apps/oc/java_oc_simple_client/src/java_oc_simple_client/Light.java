package java_oc_simple_client;

public class Light extends OcfServer {

    private long power;
    private boolean state;

    public Light() {
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
