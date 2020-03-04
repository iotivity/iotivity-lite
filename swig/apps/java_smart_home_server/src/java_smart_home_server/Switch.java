package smart_home_server;

public class Switch {

    private String name;
    private boolean value;

    public Switch(String name) {
        this(name, false);
    }

    public Switch(String name, boolean value) {
        this.name = name;
        setValue(value);
    }

    public String getName() {
        return name;
    }

    public boolean getValue() {
        return value;
    }

    public void setValue(boolean value) {
        this.value = value;
    }
}