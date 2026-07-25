package kakha.kudava;

public class App {

    public static void main(String[] args) {
        boolean created =
                NativeMath.createStoredMlKem1024Keypair();

        System.out.println(
                "ML-KEM keypair created: " + created
        );

        boolean verified =
                NativeMath.verifyStoredMlKem1024Keypair();

        System.out.println(
                "ML-KEM keypair loaded and verified: "
                        + verified
        );
    }
}