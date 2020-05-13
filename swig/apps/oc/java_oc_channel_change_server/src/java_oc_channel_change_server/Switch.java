package java_oc_channel_change_server;

public class Switch {

    private boolean value;

    public Switch() {
        this(false);
    }

    public Switch(boolean value) {
        setValue(value);
    }

    public boolean getValue() {
        return value;
    }

    public void setValue(boolean value) {
        this.value = value;
    }
}
