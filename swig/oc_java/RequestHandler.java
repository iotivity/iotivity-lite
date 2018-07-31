package org.iotivity;

public interface RequestHandler {
    public void handler(OCRequest request, int interfaces, Object user_data);
}