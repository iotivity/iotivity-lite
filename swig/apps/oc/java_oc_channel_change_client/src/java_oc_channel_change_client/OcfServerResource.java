package java_oc_channel_change_client;

import org.iotivity.OCEndpoint;

public class OcfServerResource {

    private String name;
    private OCEndpoint serverEndpoint;
    private String serverUri;

    public OcfServerResource() {
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
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
