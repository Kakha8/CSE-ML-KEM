package kakha.kudava;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

public final class App {

    public static void main(String[] args) {
        try {
            Path inputFile = getInputFile(args);

            System.out.println("File verified successfully.");
            System.out.println("Input: " + inputFile);
            System.out.println(
                    "Size: " + Files.size(inputFile) + " bytes"
            );

            boolean encrypted =
                    NativeMath.encryptSelectedFile(
                            inputFile.toString()
                    );

            System.out.println(
                    "Encryption successful: " + encrypted
            );

            if (!encrypted) {
                System.exit(1);
            }

        } catch (IllegalArgumentException | IOException error) {
            System.err.println(
                    "File validation failed: "
                            + error.getMessage()
            );

            System.exit(1);
        }
    }

    private static Path getInputFile(
            String[] args
    ) throws IOException {
        String rawPath;

        if (args.length > 0) {
            rawPath = args[0];
        } else {
            System.out.print(
                    "Enter the full path of the file to encrypt: "
            );

            BufferedReader reader =
                    new BufferedReader(
                            new InputStreamReader(System.in)
                    );

            rawPath = reader.readLine();
        }

        if (rawPath == null || rawPath.isBlank()) {
            throw new IllegalArgumentException(
                    "No file path was provided."
            );
        }

        final Path path;

        try {
            path = Path.of(rawPath.trim())
                    .toAbsolutePath()
                    .normalize();

        } catch (InvalidPathException error) {
            throw new IllegalArgumentException(
                    "The supplied path is invalid: " + rawPath,
                    error
            );
        }

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
}