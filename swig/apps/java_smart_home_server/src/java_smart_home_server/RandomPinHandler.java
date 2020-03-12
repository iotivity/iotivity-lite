package java_smart_home_server;

import org.iotivity.OCRandomPinHandler;

public class RandomPinHandler implements OCRandomPinHandler {

    @Override
    public void handler(String pin) {
        System.out.println("Inside the RandomPinHandler");

        System.out.println("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        System.out.println("Random PIN: " + pin + "\n");
        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }
}
