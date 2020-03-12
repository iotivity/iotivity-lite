package java_smart_home_server;

import java.util.List;

import org.iotivity.CborEncoder;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCQueryValue;

public class GetTemperature implements OCRequestHandler {

    private Temperature temperature;

    public GetTemperature(Temperature temperature) {
        this.temperature = temperature;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetTemperature RequestHandler");
        System.out.println("GET TEMPERATURE:");
        Temperature.Units requestedUnits = null;

        List<OCQueryValue> queryParams = OCMain.getQueryValues(request);
        if (queryParams != null) {
            for (OCQueryValue param : queryParams) {
                if (Temperature.UNITS_KEY.equalsIgnoreCase(param.getKey())) {
                    String units = param.getValue();
                    System.out.println("units: " + units);

                    if (units.equalsIgnoreCase(Temperature.Units.F.toString())) {
                        requestedUnits = Temperature.Units.F;
                    } else if (units.equalsIgnoreCase(Temperature.Units.C.toString())) {
                        requestedUnits = Temperature.Units.C;
                    } else if (units.equalsIgnoreCase(Temperature.Units.K.toString())) {
                        requestedUnits = Temperature.Units.K;
                    } else {
                        // handled below
                    }
                }
            }
        }

        CborEncoder root = OCRep.beginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE: {
            OCMain.processBaselineInterface(request.getResource());
            /* fall through */
        }
        case OCInterfaceMask.A:
        case OCInterfaceMask.S: {
            if (requestedUnits != null) {
                switch (requestedUnits) {
                case F:
                    OCRep.setDouble(root, Temperature.TEMPERATURE_KEY, temperature.getTemperatureAsF());
                    OCRep.setTextString(root, Temperature.UNITS_KEY, Temperature.Units.F.toString());
                    break;
                case C:
                    OCRep.setDouble(root, Temperature.TEMPERATURE_KEY, temperature.getTemperatureAsC());
                    OCRep.setTextString(root, Temperature.UNITS_KEY, Temperature.Units.C.toString());
                    break;
                case K:
                    OCRep.setDouble(root, Temperature.TEMPERATURE_KEY, temperature.getTemperatureAsK());
                    OCRep.setTextString(root, Temperature.UNITS_KEY, Temperature.Units.K.toString());
                    break;
                default:
                }

            } else {
                OCRep.setDouble(root, Temperature.TEMPERATURE_KEY, temperature.getTemperature());
                OCRep.setTextString(root, Temperature.UNITS_KEY, temperature.getUnits().toString());
            }
            break;
        }
        default:
            break;
        }

        CborEncoder range = OCRep.openArray(root, Temperature.RANGE_KEY);
        if (requestedUnits != null) {
            OCRep.addDouble(range, temperature.getMin(requestedUnits));
            OCRep.addDouble(range, temperature.getMax(requestedUnits));
        } else {
            OCRep.addDouble(range, temperature.getMin());
            OCRep.addDouble(range, temperature.getMax());
        }
        OCRep.closeArray(root, range);

        OCRep.endRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}
