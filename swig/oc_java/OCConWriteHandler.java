package org.iotivity;

/**
 * Interface for the OCConWriteHandler
 */
public interface OCConWriteHandler {
    /**
     * Callback handler for change notifications from the oic.wk.con resource.
     *
     * This handler is invoked to notify a change of one or more properties
     * on the oic.wk.con resource. The `rep` parameter contains all properties,
     * the function is not invoked for each property.
     *
     * When the function is invoked, all properties handled by the stack are
     * already updated. The callee can use the invocation to optionally store
     * the new values persistently.
     *
     * Once the callback returns, the response will be sent to the client
     * and observers will be notified.
     *
     * Note: As of now only the attribute "n" is supported.
     *
     * Note: The callee shall not block for too long as the stack is blocked
     * during the invocation.
     *
     * @param deviceIndex index of the device to which the change was
     *                     applied, 0 is the first device
     * @param rep list of properties and their new values
     */
    public void handler(long deviceIndex, OCRepresentation rep);
}