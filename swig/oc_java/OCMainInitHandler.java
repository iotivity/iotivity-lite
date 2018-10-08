package org.iotivity;

public interface OCMainInitHandler {
    public int initilize();
    public void signalEventLoop();
    public void registerResources();
    public void requestEntry();
}