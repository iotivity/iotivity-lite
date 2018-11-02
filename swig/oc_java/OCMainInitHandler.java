package org.iotivity;

public interface OCMainInitHandler {
    public int initialize();
    public void signalEventLoop();
    public void registerResources();
    public void requestEntry();
}