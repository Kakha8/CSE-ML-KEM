package kakha.kudava;

public class App {

    public static void main(String[] args) {
        int result = NativeMath.add(20, 22);
        System.out.println("Result returned by Rust: " + result);

        NativeMath.generateAndPrintAes256Key();

        System.out.println("\nGenerating ML-KEM-1024 keypair...");
        NativeMath.generateAndPrintMlKem1024Keypair();
    }
}