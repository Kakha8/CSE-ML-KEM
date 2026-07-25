package kakha.kudava;

public class App {

    public static void main(String[] args) {
        boolean keyPairValid =
                NativeMath.verifyStoredMlKem1024Keypair();

        System.out.println(
                "Stored ML-KEM keypair valid: " + keyPairValid
        );

        if (!keyPairValid) {
            System.err.println(
                    "Create the stored ML-KEM keypair first."
            );
            return;
        }

        boolean envelopeWorked =
                NativeMath.testStoredMlKemDekEnvelope();

        System.out.println(
                "DEK envelope round trip: " + envelopeWorked
        );
    }
}