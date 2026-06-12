package com.soundmatt.jfusa.hooks;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

/** Install/remove a pre-commit git hook that runs jfusa check. */
public final class Hooks {

    private Hooks() {}

    static final String HOOK_SCRIPT = """
            #!/bin/sh
            # jfusa pre-commit hook — installed by 'jfusa hooks install'
            # Runs jfusa check --strict before every commit.
            set -e
            if command -v jfusa >/dev/null 2>&1; then
              exec jfusa check --strict
            elif [ -f target/jfusa.jar ]; then
              exec java -jar target/jfusa.jar check --strict
            else
              echo "[jfusa] WARNING: jfusa not found in PATH or target/; skipping pre-commit check"
            fi
            """;

    public static void install(Path projectRoot) throws IOException {
        Path hooksDir = projectRoot.resolve(".git/hooks");
        if (!Files.isDirectory(hooksDir)) {
            System.err.println("Not a git repository (no .git/hooks found)");
            return;
        }
        Path hookFile = hooksDir.resolve("pre-commit");
        Files.writeString(hookFile, HOOK_SCRIPT);
        try {
            Files.setPosixFilePermissions(hookFile, PosixFilePermissions.fromString("rwxr-xr-x"));
        } catch (UnsupportedOperationException ignored) {}
        System.out.println("Pre-commit hook installed: " + hookFile);
    }

    public static void remove(Path projectRoot) throws IOException {
        Path hookFile = projectRoot.resolve(".git/hooks/pre-commit");
        if (!Files.exists(hookFile)) { System.out.println("No pre-commit hook found."); return; }
        String content = Files.readString(hookFile);
        if (content.contains("jfusa pre-commit hook")) {
            Files.delete(hookFile);
            System.out.println("Pre-commit hook removed.");
        } else {
            System.out.println("Pre-commit hook not managed by jfusa; not removed.");
        }
    }
}
