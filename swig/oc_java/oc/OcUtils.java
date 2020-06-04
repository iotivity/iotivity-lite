package org.iotivity.oc;

import java.util.List;

import org.iotivity.*;

/**
 * OcUtils is a collection of useful static methods.
 */
public class OcUtils {

    // never instantiated
    private OcUtils() {
    }

    public static List<OCQueryValue> getQueryValues(OCRequest request) {
        return OCMain.getQueryValues(request);
    }

    public static boolean doIPDiscovery(String rt, OCDiscoveryHandler handler) {
        return OCMain.doIPDiscovery(rt, handler);
    }

    public static boolean doIPDiscoveryAtEndpoint(String rt, OCDiscoveryHandler handler, OCEndpoint endpoint) {
        return OCMain.doIPDiscoveryAtEndpoint(rt, handler, endpoint);
    }

    public static boolean doIPDiscoveryAll(OCDiscoveryAllHandler handler) {
        return OCMain.doIPDiscoveryAll(handler);
    }

    public static boolean doIPDiscoveryAllAtEndpoint(OCDiscoveryAllHandler handler, OCEndpoint endpoint) {
        return OCMain.doIPDiscoveryAllAtEndpoint(handler, endpoint);
    }

    public static boolean doGet(String uri, OCEndpoint endpoint, String query, OCResponseHandler handler, OCQos qos) {
        return OCMain.doGet(uri, endpoint, query, handler, qos);
    }

    public static boolean initPut(String uri, OCEndpoint endpoint, String query, OCResponseHandler handler, OCQos qos) {
        return OCMain.initPut(uri, endpoint, query, handler, qos);
    }

    public static boolean doPut() {
        return OCMain.doPut();
    }

    public static boolean initPost(String uri, OCEndpoint endpoint, String query, OCResponseHandler handler,
            OCQos qos) {
        return OCMain.initPost(uri, endpoint, query, handler, qos);
    }

    public static boolean doPost() {
        return OCMain.doPost();
    }

    public static boolean doDelete(String uri, OCEndpoint endpoint, String query, OCResponseHandler handler,
            OCQos qos) {
        return OCMain.doDelete(uri, endpoint, query, handler, qos);
    }

    public static boolean doObserve(String uri, OCEndpoint endpoint, String query, OCResponseHandler handler,
            OCQos qos) {
        return OCMain.doObserve(uri, endpoint, query, handler, qos);
    }

    public static boolean stopObserve(String uri, OCEndpoint endpoint) {
        return OCMain.stopObserve(uri, endpoint);
    }

    public static boolean doIPMulticast(String uri, String query, OCResponseHandler handler) {
        return OCMain.doIPMulticast(uri, query, handler);
    }

    public static void stopMulticast(OCClientResponse response) {
        OCMain.stopMulticast(response);
    }

    public static void setFactoryPresetsHandler(OCFactoryPresetsHandler callback) {
        OCMain.setFactoryPresetsHandler(callback);
    }

    public static void setDelayedHandler(OCTriggerHandler callback, int seconds) {
        OCMain.setDelayedHandler(callback, seconds);
    }

    public static void setRandomPinHandler(OCRandomPinHandler callback) {
        OCMain.setRandomPinHandler(callback);
    }

    public static void removeDelayedHandler(OCTriggerHandler callback) {
        OCMain.removeDelayedHandler(callback);
    }

    public static void ignoreRequest(OCRequest request) {
        OCMain.ignoreRequest(request);
    }

    public static void sendResponse(OCRequest request, OCStatus responseCode) {
        OCMain.sendResponse(request, responseCode);
    }

    public static boolean sendPing(boolean custody, OCEndpoint endpoint, int timeoutSeconds,
            OCResponseHandler handler) {
        return OCMain.sendPing(custody, endpoint, timeoutSeconds, handler);
    }

    public static void assertAllRoles(OCEndpoint endpoint, OCResponseHandler handler) {
        OCMain.assertAllRoles(endpoint, handler);
    }

    public static boolean assertRole(String role, String authority, OCEndpoint endpoint, OCResponseHandler handler) {
        return OCMain.assertRole(role, authority, endpoint, handler);
    }

    public static boolean[] ocArrayToBooleanArray(OCArray array) {
        return OCRep.ocArrayToBooleanArray(array);
    }

    public static long[] ocArrayToLongArray(OCArray array) {
        return OCRep.ocArrayToLongArray(array);
    }

    public static double[] ocArrayToDoubleArray(OCArray array) {
        return OCRep.ocArrayToDoubleArray(array);
    }

    public static String[] ocArrayToStringArray(OCArray array) {
        return OCRep.ocArrayToStringArray(array);
    }

    public static String endpointToString(OCEndpoint endpoint) {
        return OCEndpointUtil.toString(endpoint);
    }

    public static void closeSession(OCEndpoint endpoint) {
        OCMain.closeSession(endpoint);
    }

    public static void freeServerEndpoints(OCEndpoint endpoint) {
        OCMain.freeServerEndpoints(endpoint);
    }

    /**
     * Discovers all devices.
     *
     * @param deviceDiscoveryHandler  the callback interface
     * @return true if the discovery request is successful, false otherwise
     *
     * @see OcDeviceDiscoveryHandler#discoveredDevice
     */
    public static boolean discoverAllDevices(OcDeviceDiscoveryHandler deviceDiscoveryHandler) {
        return OcUtils.doIPMulticast("/oic/d", null, new OcGetRemoteDeviceHandler(deviceDiscoveryHandler));
    }
}
