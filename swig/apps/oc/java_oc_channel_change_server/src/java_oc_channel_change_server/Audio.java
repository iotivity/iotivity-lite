package java_oc_channel_change_server;

public class Audio {

    static public final int MAX_VOLUME = 100;
    static public final int MIN_VOLUME = 0;

    private boolean mute;
    private int volume;

    public Audio() {
        this(false, MIN_VOLUME);
    }

    public Audio(boolean mute, int volume) {
        setMute(mute);
        setVolume(volume);
    }

    public boolean isMute() {
        return mute;
    }

    public void setMute(boolean mute) {
        this.mute = mute;
    }

    public int getVolume() {
        return volume;
    }

    public void setVolume(int volume) {
        volume = Math.min(volume, MAX_VOLUME);
        volume = Math.max(volume, MIN_VOLUME);
        this.volume = volume;
    }
}
