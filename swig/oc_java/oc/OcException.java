package org.iotivity.oc;

import org.iotivity.*;

/**
 * OcException is the base class of all org.iotivity.oc exceptions.
 */
public class OcException extends Exception {

    public OcException(String message) {
        super(message);
    }
}
