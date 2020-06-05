package java_oc_dummy_bridge;

import org.iotivity.*;
import org.iotivity.oc.*;

public class DummyVirtualLight extends OcVirtualDevice {
    private String uuid;
    private boolean on;
    private boolean discovered;
    private boolean addedToBridge;

    public DummyVirtualLight(String deviceName, String uuid, String ecoSystem,
            boolean on, boolean discovered, boolean addedToBridge) {
        super(uuid.getBytes(), ecoSystem, "/oic/d", "oic.d.light", deviceName,
                "ocf.2.0.0", "ocf.res.1.0.0,ocf.sh.1.0.0", new OCAddDeviceHandler() {
                    public void handler() {
                        System.out.println("inside DummyVirtualLight.OCAddDeviceHandler.handler()");
                    }
                });
        this.uuid = uuid;
        setImmutableDeviceId(OCUuidUtil.stringToUuid(uuid));
        setOn(on);
        setDiscovered(discovered);
        setAddedToBridge(addedToBridge);
    }

    public String getUuid() {
        return uuid;
    }

    public boolean isOn() {
        return on;
    }

    public void setOn(boolean on) {
        this.on = on;
    }

    public boolean isDiscovered() {
        return discovered;
    }

    public void setDiscovered(boolean discovered) {
        this.discovered = discovered;
    }

    public boolean isAddedToBridge() {
        return addedToBridge;
    }

    public void setAddedToBridge(boolean addedToBridge) {
        this.addedToBridge = addedToBridge;
    }
}
