package java_smart_home_server;

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
