package org.iotivity;

public interface MainInitHandler {
    public int initilize();
    public void signalEventLoop();
    public void registerResources();
    public void requestEntry();
}