package java_smart_home_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCRepresentation;
import org.iotivity.OCStatus;

public class PostTemperature implements OCRequestHandler {

    private Temperature temperature;

    public PostTemperature(Temperature temperature) {
        this.temperature = temperature;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostTemperature RequestHandler");
        System.out.println("POST TEMPERATURE:");
        boolean outOfRange = false;
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch (rep.getType()) {
            case OC_REP_DOUBLE:
                temperature.setTemperature(rep.getValue().getDouble());
                System.out.println("value: " + temperature.getTemperature());
                break;
            case OC_REP_STRING:
                if (rep.getValue().getString().equalsIgnoreCase(Temperature.Units.F.toString())) {
                    temperature.setUnits(Temperature.Units.F);
                } else if (rep.getValue().getString().equalsIgnoreCase(Temperature.Units.C.toString())) {
                    temperature.setUnits(Temperature.Units.C);
                } else if (rep.getValue().getString().equalsIgnoreCase(Temperature.Units.K.toString())) {
                    temperature.setUnits(Temperature.Units.K);
                } else {
                    outOfRange = true;
                }

                if (outOfRange) {
                    System.out.println("unexpected value: " + rep.getValue().getString());
                } else {
                    System.out.println("value: " + temperature.getUnits().toString());
                }
                break;
            default:
                outOfRange = true;
                System.out.println("UNEXPECTED TYPE");
            }
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }

        outOfRange |= !temperature.isInRange();

        CborEncoder root = OCRep.beginRootObject();
        OCRep.setDouble(root, Temperature.TEMPERATURE_KEY, temperature.getTemperature());
        OCRep.setTextString(root, Temperature.UNITS_KEY, temperature.getUnits().toString());

        CborEncoder range = OCRep.openArray(root, Temperature.RANGE_KEY);
        OCRep.addDouble(range, temperature.getMin());
        OCRep.addDouble(range, temperature.getMax());
        OCRep.closeArray(root, range);
        OCRep.endRootObject();

        OCMain.sendResponse(request, outOfRange ? OCStatus.OC_STATUS_FORBIDDEN : OCStatus.OC_STATUS_CHANGED);
    }
}
