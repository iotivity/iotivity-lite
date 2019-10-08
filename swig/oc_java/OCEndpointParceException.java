package org.iotivity;

public class OCEndpointParceException extends Exception {
    private static final long serialVersionUID = -5160712938956585665L;
    private String parsedData;

    public OCEndpointParceException(String message) {
        super(message);
    }
}
