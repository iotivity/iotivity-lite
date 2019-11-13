package java_oc_simple_client;

import org.iotivity.OCEndpoint;
import org.iotivity.OCEndpointUtil;

public class OcfServer {

    private String name;
    private OCEndpoint serverEndpoint;
    private String serverUri;

    public OcfServer() {
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
        this.serverEndpoint = OCEndpointUtil.listCopy(serverEndpoint);
    }

    public String getServerUri() {
        return serverUri;
    }

    public void setServerUri(String serverUri) {
        this.serverUri = serverUri;
    }
}
