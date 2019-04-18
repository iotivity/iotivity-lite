package org.iotivity.oc;

import java.util.List;

import org.iotivity.*;

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
        String[] endpointString = new String[1];
        OCEndpointUtil.toString(endpoint, endpointString);
        return endpointString[0];
    }

    public static void closeSession(OCEndpoint endpoint) {
        OCMain.closeSession(endpoint);
    }

    public static void freeServerEndpoints(OCEndpoint endpoint) {
        OCMain.freeServerEndpoints(endpoint);
    }
}
