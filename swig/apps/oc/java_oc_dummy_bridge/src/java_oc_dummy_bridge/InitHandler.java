package java_oc_dummy_bridge;

import org.iotivity.*;
import org.iotivity.oc.*;

public class InitHandler implements OCMainInitHandler {

    private OcPlatform platform;

    public InitHandler(OcPlatform platform) {
        this.platform = platform;
    }

    @Override
    public int initialize() {
        System.out.println("inside InitHandler.initialize()");
        int ret = platform.platformInit("Intel");
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
