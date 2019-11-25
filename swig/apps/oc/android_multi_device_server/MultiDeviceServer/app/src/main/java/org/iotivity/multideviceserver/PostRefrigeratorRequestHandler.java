package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcCborException;
import org.iotivity.oc.OcRepresentation;
import org.iotivity.oc.OcUtils;

public class PostRefrigeratorRequestHandler implements OCRequestHandler {

    private static final String TAG = PostRefrigeratorRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Refrigerator refrigerator;

    public PostRefrigeratorRequestHandler(ServerActivity activity, Refrigerator refrigerator) {
        this.activity = activity;
        this.refrigerator = refrigerator;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Post Refrigerator Request Handler");

        activity.msg("Post Refrigerator:");

        OcRepresentation rep = new OcRepresentation(request.getRequestPayload());
        while (rep != null) {
            try {
                if (Refrigerator.FILTER_KEY.equalsIgnoreCase(rep.getKey())) {
                    refrigerator.setFilter((int) rep.getLong(Refrigerator.FILTER_KEY));
                    activity.msg("\t\t" + Refrigerator.FILTER_KEY + ": " + refrigerator.getFilter());
                }
            } catch (OcCborException e) {
                // ignore -- no filter value
            }

            try {
                if (Refrigerator.RAPID_FREEZE_KEY.equalsIgnoreCase(rep.getKey())) {
                    refrigerator.setRapidFreeze(rep.getBoolean(Refrigerator.RAPID_FREEZE_KEY));
                    activity.msg("\t\t" + Refrigerator.RAPID_FREEZE_KEY + ": " + refrigerator.isRapidFreeze());
                }
            } catch (OcCborException e) {
                // ignore -- no rapid freeze value
            }

            try {
                if (Refrigerator.RAPID_COOL_KEY.equalsIgnoreCase(rep.getKey())) {
                    refrigerator.setRapidCool(rep.getBoolean(Refrigerator.RAPID_COOL_KEY));
                    activity.msg("\t\t" + Refrigerator.RAPID_COOL_KEY + ": " + refrigerator.isRapidCool());
                }
            } catch (OcCborException e) {
                // ignore -- no rapid cool value
            }

            try {
                if (Refrigerator.DEFROST_KEY.equalsIgnoreCase(rep.getKey())) {
                    refrigerator.setDefrost(rep.getBoolean(Refrigerator.DEFROST_KEY));
                    activity.msg("\t\t" + Refrigerator.DEFROST_KEY + ": " + refrigerator.isDefrost());
                }
            } catch (OcCborException e) {
                // ignore -- no defrost value
            }

            rep = rep.getNext();
        }

        activity.printLine();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}
