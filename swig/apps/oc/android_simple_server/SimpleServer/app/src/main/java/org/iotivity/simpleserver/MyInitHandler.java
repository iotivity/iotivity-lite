package org.iotivity.simpleserver;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMainInitHandler;
import org.iotivity.oc.OcDevice;
import org.iotivity.oc.OcPlatform;
import org.iotivity.oc.OcResource;
import org.iotivity.oc.OcUtils;

public class MyInitHandler implements OCMainInitHandler {

    private static final String TAG = MyInitHandler.class.getSimpleName();

    private ServerActivity activity;
    private OcPlatform obtPlatform;

    private OcDevice device;
    private Light light;

    public MyInitHandler(ServerActivity activity, OcPlatform obtPlatform) {
        this.activity = activity;
        this.obtPlatform = obtPlatform;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside MyInitHandler.initialize()");
        int ret = obtPlatform.platformInit("Intel");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0", "ocf.res.1.0.0");
            ret |= obtPlatform.addDevice(device);
        }

        light = new Light();
        light.name = "John's Light";

        OcUtils.setRandomPinHandler(new RandomPinHandler(activity));
        return ret;
    }

    @Override
    public void registerResources() {
        Log.d(TAG, "inside MyInitHandler.registerResources()");

        String[] resourceTypes = new String[]{"core.light", "core.brightlight"};
        int[] interfaceMasks = new int[]{OCInterfaceMask.RW};

        OcResource resource = new OcResource(device, "light", "/a/light", resourceTypes, interfaceMasks);
        resource.setDefaultInterfaceMask(OCInterfaceMask.RW);
        resource.setDiscoverable(true);
        resource.setObservable(true);
        resource.setPeriodicObservable(1);
        resource.setGetRequestHandler(new GetLightRequestHandler(activity, light));
        resource.setPutRequestHandler(new PutLightRequestHandler(activity, light));
        resource.setPostRequestHandler(new PostLightRequestHandler(activity, light));
        device.addResource(resource);
    }

    @Override
    public void requestEntry() {
        Log.d(TAG, "inside MyInitHandler.requestEntry()");
    }
}
