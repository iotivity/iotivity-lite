package java_dummy_bridge;

import org.iotivity.*;

public class InitHandler implements OCMainInitHandler {

    @Override
    public int initialize() {
        System.out.println("inside InitHandler.initialize()");
        int ret = OCMain.initPlatform("Desktop PC");
        ret |= OCBridge.addBridgeDevice("Dummy Bridge", "ocf.1.0.0", "ocf.res.1.0.0");
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside InitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        System.out.println("inside InitHandler.requestEntry()");
    }
}
