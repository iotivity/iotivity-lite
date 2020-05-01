package java_oc_channel_change_server;

import org.iotivity.*;

public class PutAudio implements OCRequestHandler {

    private Audio audioControl;

    public PutAudio(Audio audioControl) {
        this.audioControl = audioControl;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PutAudio RequestHandler");
        new PostAudio(audioControl).handler(request, interfaces);
    }
}
