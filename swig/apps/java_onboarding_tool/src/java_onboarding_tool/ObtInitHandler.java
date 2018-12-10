package java_onboarding_tool;

import org.iotivity.OCMain;
import org.iotivity.OCMainInitHandler;
import org.iotivity.OCObt;

public class ObtInitHandler implements OCMainInitHandler {

    @Override
    public int initialize() {
        System.out.println("inside ObtInitHandler.initilize()");
        int ret = OCMain.initPlatform("OCF");
        ret |= OCMain.addDevice("/oic/d", "oic.d.phone", "OBT", "ocf.1.0.0", "ocf.res.1.0.0");
        return ret;
    }


    @Override
    public void registerResources() {
        System.out.println("inside ObtInitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        System.out.println("inside ObtInitHandler.requestEntry()");
        OCObt.init();
    }

    @Override
    public void signalEventLoop() {
        //System.out.println("inside MyInitHandler.signalEventLoop()");
        ObtMain.lock.lock();
        try {
            ObtMain.cv.signalAll();
        } finally {
            ObtMain.lock.unlock();
        }
    }
}
