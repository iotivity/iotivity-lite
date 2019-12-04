package org.iotivity.simpleserver;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMainInitHandler;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcDevice;
import org.iotivity.oc.OcPlatform;
import org.iotivity.oc.OcResource;
import org.iotivity.oc.OcUtils;

public class MyInitHandler implements OCMainInitHandler {

    private static final String TAG = MyInitHandler.class.getSimpleName();

    private ServerActivity activity;
    private OcPlatform ocPlatform;

    private OcDevice device;
    private Light light;

    public MyInitHandler(ServerActivity activity, OcPlatform ocPlatform) {
        this.activity = activity;
        this.ocPlatform = ocPlatform;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside MyInitHandler.initialize()");
        int ret = ocPlatform.platformInit("Intel");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.light", "Lamp", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
            ret |= ocPlatform.addDevice(device);
        }

        light = new Light();
        light.name = "John's Light";

        OcUtils.setRandomPinHandler(new RandomPinHandler(activity));
        return ret;
    }

    @Override
    public void registerResources() {
        Log.d(TAG, "inside MyInitHandler.registerResources()");

        String[] resourceTypes = new String[]{"oic.r.switch.binary", "oic.r.light.dimming"};
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
        Log.d(TAG, "\tDeviceId = " + OCUuidUtil.uuidToString(device.getId()));
    }
}
