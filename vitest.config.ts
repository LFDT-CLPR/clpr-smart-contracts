import {defineConfig} from "vitest/config";

export default defineConfig({
    test: {
        globalSetup: ["test/e2e/backend/solo/solo.ts"],
        include: ["test/e2e/**/*.spec.ts"],
        exclude: ["**/node_modules/**", "**/dist/**", "test/e2e/tests/security/**"],
        globals: true,
        testTimeout: 120_000,
        hookTimeout: 180_000,
        pool: "forks",
        fileParallelism: false,
        maxWorkers: 1,
        sequence: {concurrent: false},
        reporters: process.env.CI ? ["default", "junit"] : ["default"],
        outputFile: process.env.CI
            ? process.env.CLPR_E2E_FEE_TOKEN === "1" ? "junit-token.xml" : "junit.xml"
            : undefined
    }
});
