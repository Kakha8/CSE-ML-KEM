package kakha.kudava;

public final class NativeMath {

    static {
        System.loadLibrary("native_rust");
    }

    private NativeMath() {
    }

    public static native boolean createStoredMlKem1024Keypair();

    public static native boolean verifyStoredMlKem1024Keypair();

    public static native boolean testStoredMlKemDekEnvelope();

    public static native boolean encryptSelectedFile(
            String inputPath
    );

    public static native boolean decryptSelectedFile(
            String inputPath
    );

    public static native boolean decryptSelectedFileTo(
            String inputPath,
            String outputPath,
            boolean overwrite
    );
}