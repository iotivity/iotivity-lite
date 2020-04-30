package org.iotivity.oc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.iotivity.*;

public class OcPlatform {

    private AtomicInteger deviceIndex = new AtomicInteger();
    private Map<OcDevice, AtomicInteger> deviceIndexLookup = new ConcurrentHashMap<>();

    private static OcPlatform instance;

    private OcPlatform() {
    }

    public static OcPlatform getInstance() {
        if (instance == null) {
            instance = new OcPlatform();
        }

        return instance;
    }

    public void systemShutdown() {
        OCMain.mainShutdown();
        deviceIndex.set(0);
        deviceIndexLookup.clear();
    }

    public void systemInit(OCMainInitHandler mainInitHandler) {
        int initReturnValue = OCMain.mainInit(mainInitHandler);
        if (initReturnValue < 0) {
            System.exit(initReturnValue);
        }
    }

    public int platformInit(String mfgName) {
        mfgName = (mfgName != null) ? mfgName : "";
        return OCMain.initPlatform(mfgName);
    }

    public void reset() {
        OCMain.reset();
    }

    public int addDevice(OcDevice device) {
        int ret = -1;

        if (device != null) {
            // tell the device its index
            device.setDeviceIndex(deviceIndex.get());

            // save the current device index for future lookup
            deviceIndexLookup.put(device, deviceIndex);

            ret = OCMain.addDevice(device.getUri(), device.getRt(), device.getName(), device.getSpecVersion(),
                    device.getDataModelVersion());

            if (ret >= 0) {
                deviceIndex.getAndIncrement(); // get ready for next device
            }
        }

        return ret;
    }
}
