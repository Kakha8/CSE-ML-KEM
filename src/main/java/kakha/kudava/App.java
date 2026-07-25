package kakha.kudava;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

public final class App {

    private static final BufferedReader CONSOLE =
            new BufferedReader(new InputStreamReader(System.in));

    private App() {
    }

    public static void main(String[] args) {
        System.out.println("================================");
        System.out.println("       CSE-ML-KEM File Tool");
        System.out.println("================================");

        while (true) {
            printMenu();

            final String choice;

            try {
                choice = CONSOLE.readLine();
            } catch (IOException error) {
                System.err.println(
                        "Could not read terminal input: "
                                + error.getMessage()
                );
                return;
            }

            if (choice == null) {
                System.out.println("\nTerminal input closed.");
                return;
            }

            switch (choice.trim()) {
                case "1" -> encryptFile();
                case "2" -> decryptFile();
                case "3" -> {
                    System.out.println("Goodbye.");
                    return;
                }
                default -> System.err.println(
                        "Invalid option. Enter 1, 2, or 3."
                );
            }

            System.out.println();
        }
    }

    private static void printMenu() {
        System.out.println();
        System.out.println("1) Encrypt file");
        System.out.println("2) Decrypt file");
        System.out.println("3) Exit");
        System.out.print("Select an option: ");
    }

    private static void encryptFile() {
        try {
            Path inputFile = promptForExistingFile(
                    "Enter the full path of the file to encrypt: "
            );

            System.out.println();
            printFileInformation(inputFile);

            boolean encrypted =
                    NativeMath.encryptSelectedFile(
                            inputFile.toString()
                    );

            if (encrypted) {
                Path expectedOutput = inputFile.resolveSibling(
                        inputFile.getFileName() + ".cseml"
                );

                System.out.println();
                System.out.println("Encryption successful.");
                System.out.println(
                        "Encrypted file: " + expectedOutput
                );
            } else {
                System.err.println();
                System.err.println(
                        "Encryption failed. Check the Rust output above."
                );
            }

        } catch (IllegalArgumentException | IOException error) {
            System.err.println(
                    "File validation failed: "
                            + error.getMessage()
            );
        }
    }

    private static void decryptFile() {
        try {
            Path encryptedFile = promptForExistingFile(
                    "Enter the full path of the .cseml file to decrypt: "
            );

            verifyCsemlExtension(encryptedFile);

            System.out.println();
            printFileInformation(encryptedFile);

            Path outputFile = getOriginalOutputPath(encryptedFile);
            boolean overwrite = false;

            if (Files.exists(outputFile)) {
                DecryptionDecision decision =
                        askExistingOutputDecision(
                                encryptedFile,
                                outputFile
                        );

                if (decision == null) {
                    System.out.println("Decryption cancelled.");
                    return;
                }

                outputFile = decision.outputFile();
                overwrite = decision.overwrite();
            }

            boolean decrypted =
                    NativeMath.decryptSelectedFileTo(
                            encryptedFile.toString(),
                            outputFile.toString(),
                            overwrite
                    );

            if (decrypted) {
                System.out.println();
                System.out.println("Decryption successful.");
                System.out.println(
                        "Decrypted file: " + outputFile
                );
            } else {
                System.err.println();
                System.err.println(
                        "Decryption failed. Check the specific Rust error above."
                );
            }

        } catch (IllegalArgumentException | IOException error) {
            System.err.println(
                    "File validation failed: "
                            + error.getMessage()
            );
        }
    }

    private static DecryptionDecision askExistingOutputDecision(
            Path encryptedFile,
            Path existingOutput
    ) throws IOException {
        while (true) {
            System.out.println();
            System.out.println("The original output already exists:");
            System.out.println(existingOutput);
            System.out.println();
            System.out.println("1) Cancel");
            System.out.println("2) Save with a different name");
            System.out.println("3) Overwrite the existing file");
            System.out.print("Select an option: ");

            String choice = CONSOLE.readLine();

            if (choice == null) {
                return null;
            }

            switch (choice.trim()) {
                case "1" -> {
                    return null;
                }

                case "2" -> {
                    Path differentOutput = promptForNewOutputPath(
                            encryptedFile
                    );

                    return new DecryptionDecision(
                            differentOutput,
                            false
                    );
                }

                case "3" -> {
                    System.out.println();
                    System.out.println(
                            "This will replace: " + existingOutput
                    );
                    System.out.print(
                            "Type OVERWRITE to confirm: "
                    );

                    String confirmation = CONSOLE.readLine();

                    if ("OVERWRITE".equals(confirmation)) {
                        return new DecryptionDecision(
                                existingOutput,
                                true
                        );
                    }

                    System.out.println(
                            "Confirmation did not match. Decryption cancelled."
                    );
                    return null;
                }

                default -> System.err.println(
                        "Invalid option. Enter 1, 2, or 3."
                );
            }
        }
    }

    private static Path promptForNewOutputPath(
            Path encryptedFile
    ) throws IOException {
        System.out.print(
                "Enter the full output path, including the file extension: "
        );

        String rawPath = CONSOLE.readLine();

        if (rawPath == null || rawPath.isBlank()) {
            throw new IllegalArgumentException(
                    "No output path was provided."
            );
        }

        Path outputPath = parsePath(rawPath);

        Path parent = outputPath.getParent();

        if (parent == null || !Files.isDirectory(parent)) {
            throw new IllegalArgumentException(
                    "The output directory does not exist: " + parent
            );
        }

        if (Files.exists(outputPath)) {
            throw new IllegalArgumentException(
                    "The alternate output already exists: " + outputPath
            );
        }

        if (outputPath.equals(encryptedFile)) {
            throw new IllegalArgumentException(
                    "The output cannot be the encrypted input file."
            );
        }

        return outputPath;
    }

    private static Path promptForExistingFile(
            String prompt
    ) throws IOException {
        System.out.print(prompt);

        String rawPath = CONSOLE.readLine();

        if (rawPath == null || rawPath.isBlank()) {
            throw new IllegalArgumentException(
                    "No file path was provided."
            );
        }

        Path path = parsePath(rawPath);

        if (!Files.exists(path)) {
            throw new IllegalArgumentException(
                    "The file does not exist: " + path
            );
        }

        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException(
                    "The path is not a regular file: " + path
            );
        }

        if (!Files.isReadable(path)) {
            throw new IllegalArgumentException(
                    "The file is not readable: " + path
            );
        }

        return path.toRealPath();
    }

    private static Path parsePath(String rawPath) {
        String value = removeSurroundingQuotes(rawPath.trim());

        try {
            return Path.of(value)
                    .toAbsolutePath()
                    .normalize();

        } catch (InvalidPathException error) {
            throw new IllegalArgumentException(
                    "The supplied path is invalid: " + value,
                    error
            );
        }
    }

    private static void verifyCsemlExtension(Path file) {
        String name = file.getFileName().toString();

        if (!name.toLowerCase().endsWith(".cseml")) {
            throw new IllegalArgumentException(
                    "The encrypted input must end with .cseml"
            );
        }
    }

    private static Path getOriginalOutputPath(
            Path encryptedFile
    ) {
        String encryptedName =
                encryptedFile.getFileName().toString();

        String originalName = encryptedName.substring(
                0,
                encryptedName.length() - ".cseml".length()
        );

        if (originalName.isBlank()) {
            throw new IllegalArgumentException(
                    "The encrypted filename does not contain an original name."
            );
        }

        return encryptedFile.resolveSibling(originalName);
    }

    private static String removeSurroundingQuotes(
            String value
    ) {
        if (value.length() >= 2) {
            boolean doubleQuoted =
                    value.startsWith("\"")
                            && value.endsWith("\"");

            boolean singleQuoted =
                    value.startsWith("'")
                            && value.endsWith("'");

            if (doubleQuoted || singleQuoted) {
                return value.substring(
                        1,
                        value.length() - 1
                );
            }
        }

        return value;
    }

    private static void printFileInformation(
            Path file
    ) throws IOException {
        System.out.println("File verified successfully.");
        System.out.println("Path: " + file);
        System.out.println("Name: " + file.getFileName());
        System.out.println(
                "Size: " + Files.size(file) + " bytes"
        );
    }

    private record DecryptionDecision(
            Path outputFile,
            boolean overwrite
    ) {
    }
}