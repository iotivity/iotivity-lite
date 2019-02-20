package org.iotivity.simpleserver;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCMainInitHandler;
import org.iotivity.OCMethod;
import org.iotivity.OCResource;

public class MyInitHandler implements OCMainInitHandler {

    private static final String TAG = MyInitHandler.class.getSimpleName();

    private ServerActivity activity;
    private Light light;

    public MyInitHandler(ServerActivity activity) {
        this.activity = activity;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside MyInitHandler.initialize()");
        int ret = OCMain.initPlatform("Intel");
        ret |= OCMain.addDevice("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0", "ocf.res.1.0.0");
        return ret;
    }

    @Override
    public void registerResources() {
        Log.d(TAG, "inside MyInitHandler.registerResources()");
        OCResource resource = OCMain.newResource("", "/a/light", (short) 2, 0);
        OCMain.resourceBindResourceType(resource, "core.light");
        OCMain.resourceBindResourceType(resource, "core.brightlight");
        OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.RW);
        OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.RW);
        OCMain.resourceSetDiscoverable(resource, true);
        OCMain.resourceSetPeriodicObservable(resource, 1);

        light = new Light();
        light.name = "John's Light";
        light.power = 0;
        light.state = false;

        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, new GetLightRequestHandler(activity, light));
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_PUT, new PutLightRequestHandler(activity, light));
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, new PostLightRequestHandler(activity, light));
        OCMain.addResource(resource);
    }

    @Override
    public void requestEntry() {
        Log.d(TAG, "inside MyInitHandler.requestEntry()");
    }

    @Override
    public void signalEventLoop() {
        Log.d(TAG, "inside MyInitHandler.signalEventLoop()");
        activity.lock.lock();
        try {
            activity.cv.signalAll();
        } finally {
            activity.lock.unlock();
        }
    }
}
