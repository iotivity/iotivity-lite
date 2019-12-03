package java_oc_onboarding_tool;

import org.iotivity.OCObtStatusHandler;

public class ProvisionIdCertificateHandler implements OCObtStatusHandler {

    @Override
    public void handler(int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully provisioned identity certificate");
        } else {
            System.out.println("\nERROR provisioning identity certificate");
        }
    }
}
