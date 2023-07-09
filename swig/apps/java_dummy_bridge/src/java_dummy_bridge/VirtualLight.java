package java_dummy_bridge;

public class VirtualLight {
    public String deviceName;
    public String uuid;
    public String ecoSystem;
    public boolean on;
    public boolean discovered;
    public boolean addedToBridge;

    public VirtualLight(String deviceName, String uuid, String ecoSystem,
                        boolean on, boolean discovered, boolean addedToBridge) {
        this.deviceName = deviceName;
        this.uuid = uuid;
        this.ecoSystem = ecoSystem;
        this.on = on;
        this.discovered = discovered;
        this.addedToBridge = addedToBridge;
    }
}
