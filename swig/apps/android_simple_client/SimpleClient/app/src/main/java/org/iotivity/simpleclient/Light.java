package org.iotivity.simpleclient;

import org.iotivity.OCEndpoint;

public class Light {
    public String name;
    public long power;
    public boolean state;

    public OCEndpoint serverEndpoint;
    public String serverUri;
}
