package java_multi_device_client;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCRep;
import org.iotivity.OCRepresentation;
import org.iotivity.OCResponseHandler;

public class GetTemperatureResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Temperature Response Handler:");
        OCRepresentation rep = response.getPayload();
        while(rep != null) {
            switch(rep.getType()) {
            case OC_REP_DOUBLE:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getDouble());
                Thermostat.temperature =  rep.getValue().getDouble();
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }

        if (!Client.stopGetPost && 
            OCMain.initPost(Thermostat.serverUri, Thermostat.serverEndpoint, null, Client.postTemperature, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setDouble(root, "temperature", Thermostat.temperature + 1.0);
            OCRep.endRootObject();
            if (OCMain.doPost()) {
                System.out.println("\tSent POST request");
            } else {
                System.out.println("\tCould not send POST request");
            }
        } else {
            System.out.println("\tCould not init POST request");
        }
    }
}
