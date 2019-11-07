package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class ProvisionCredentialsHandler implements OCObtStatusHandler {

    @Override
    public void handler(int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully provisioned pair-wise credentials");
        } else {
            System.out.println("\nERROR provisioning pair-wise credentials");
        }
    }
}
