package java_oc_channel_change_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostAudio implements OCRequestHandler {

    private Audio audioControl;

    public PostAudio(Audio audioControl) {
        this.audioControl = audioControl;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostAudio RequestHandler");
        OcRepresentation rep = new OcRepresentation(request.getRequestPayload());
        while (rep != null) {
            try {
                if ("mute".equalsIgnoreCase(rep.getKey())) {
                    boolean mute = rep.getBoolean("mute");
                    System.out.println("mute: " + mute);
                    audioControl.setMute(mute);
                }
            } catch (OcCborException e) {
                // ignore -- no mute
            }

            try {
                if ("volume".equalsIgnoreCase(rep.getKey())) {
                    int volume = (int) rep.getLong("volume");
                    System.out.println("volume: " + volume);
                    audioControl.setVolume(volume);
                }
            } catch (OcCborException e) {
                // ignore -- no volume
            }

            rep = rep.getNext();
        }

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        GetAudio.encodeReturnValue(root, audioControl);
        root.done();

        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}
