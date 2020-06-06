package org.iotivity.oc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.iotivity.*;

/**
 * OcPlatform is the basic building block of every IoTivity server or client.
 * <p>
 * A typical usage pattern would be:
 * <pre>
 * OcPlatform platform = OcPlatform.getInstance();
 * OCMainInitHandler handler = new InitHandler(platform); // InitHandler is an instance of OCMainInitHandler
 * platform.systemInit(handler);
 * </pre>
 * @see OCMainInitHandler
 */
public class OcPlatform {

    private AtomicInteger deviceIndex = new AtomicInteger();
    private Map<OcDevice, AtomicInteger> deviceIndexLookup = new ConcurrentHashMap<>();

    private static OcPlatform instance;

    private OcPlatform() {
    }

    /**
     * Returns the single platform instance.
     *
     * @return the OcPlatform instance
     */
    public static OcPlatform getInstance() {
        if (instance == null) {
            instance = new OcPlatform();
        }

        return instance;
    }

    /**
     * Ends the lifetime of the IoTivity server or client.
     */
    public void systemShutdown() {
        OCMain.mainShutdown();
        deviceIndex.set(0);
        deviceIndexLookup.clear();
    }

    /**
     * Begins the lifetime of the IoTivity server or client.
     *
     * @param mainInitHandler  an instance of OCMainInitHandler
     *
     * @see OCMainInitHandler
     */
    public void systemInit(OCMainInitHandler mainInitHandler) {
        int initReturnValue = OCMain.mainInit(mainInitHandler);
        if (initReturnValue < 0) {
            System.exit(initReturnValue);
        }
    }

    /**
     * Initializes the platform.  Should be called from OCMainInitHandler.initialize().
     *
     * @param mfgName  the manufacturer's name of this platform
     * @return -1 on failure, &gt;=0 otherwise
     *
     * @see OCMainInitHandler#initialize
     */
    public int platformInit(String mfgName) {
        mfgName = (mfgName != null) ? mfgName : "";
        return OCMain.initPlatform(mfgName);
    }

    /**
     * Resets the platform.
     */
    public void reset() {
        OCMain.reset();
    }

    /**
     * Adds a device to the platform.
     *
     * @param device  the OcDevice to add to this platform
     * @return -1 on failure, &gt;=0 otherwise
     *
     * @see OcDevice
     */
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
