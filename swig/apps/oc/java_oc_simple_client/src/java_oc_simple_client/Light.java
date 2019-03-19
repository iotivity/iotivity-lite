package java_oc_simple_client;

import org.iotivity.OCEndpoint;

public class Light {

    private String name;
    private int power;
    private boolean state;
    private OCEndpoint serverEndpoint;
    private String serverUri;

    public Light() {
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

    public OCEndpoint getServerEndpoint() {
        return serverEndpoint;
    }

    public void setServerEndpoint(OCEndpoint serverEndpoint) {
        this.serverEndpoint = serverEndpoint;
    }

    public String getServerUri() {
        return serverUri;
    }

    public void setServerUri(String serverUri) {
        this.serverUri = serverUri;
    }
}
