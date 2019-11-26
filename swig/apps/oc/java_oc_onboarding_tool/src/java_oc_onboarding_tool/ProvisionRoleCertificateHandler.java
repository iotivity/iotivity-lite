package java_oc_onboarding_tool;

import org.iotivity.OCObtStatusHandler;

public class ProvisionRoleCertificateHandler implements OCObtStatusHandler {

    @Override
    public void handler(int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully provisioned role certificate");
        } else {
            System.out.println("\nERROR provisioning role certificate");
        }
    }
}
