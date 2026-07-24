package kakha.kudava;

public final class NativeMath {

    static {
        System.loadLibrary("native_rust");
    }

    private NativeMath() {
    }

    public static native int add(int left, int right);

    public static native void generateAndPrintAes256Key();
    public static native void generateAndPrintMlKem1024Keypair();

}