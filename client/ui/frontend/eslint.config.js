import js from "@eslint/js";
import tseslint from "typescript-eslint";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import jsxA11y from "eslint-plugin-jsx-a11y";
import globals from "globals";

export default tseslint.config(
    {
        ignores: ["dist/**", "node_modules/**", "bindings/**", "sonar/**"],
    },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
        files: ["src/**/*.{ts,tsx}"],
        plugins: {
            react,
            "react-hooks": reactHooks,
            "react-refresh": reactRefresh,
            "jsx-a11y": jsxA11y,
        },
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: "module",
            globals: { ...globals.browser },
            parserOptions: {
                ecmaFeatures: { jsx: true },
            },
        },
        settings: {
            react: { version: "detect" },
        },
        rules: {
            // ----- a11y / semantic HTML (jsx-a11y recommended) -----
            ...jsxA11y.configs.recommended.rules,
            "jsx-a11y/no-autofocus": ["warn", { ignoreNonDOM: true }],

            // ----- React -----
            ...react.configs.recommended.rules,
            ...react.configs["jsx-runtime"].rules,
            "react/prop-types": "off",
            "react/jsx-no-target-blank": ["error", { allowReferrer: true }],
            "react/self-closing-comp": "warn",

            // ----- React hooks -----
            "react-hooks/rules-of-hooks": "error",
            "react-hooks/exhaustive-deps": "warn",

            // ----- Vite / HMR (Fast Refresh) -----
            "react-refresh/only-export-components": "off",

            // ----- TypeScript -----
            "@typescript-eslint/no-unused-vars": [
                "warn",
                {
                    argsIgnorePattern: "^_",
                    varsIgnorePattern: "^_",
                    caughtErrorsIgnorePattern: "^_",
                },
            ],
            "@typescript-eslint/consistent-type-imports": [
                "warn",
                { prefer: "type-imports", fixStyle: "inline-type-imports" },
            ],
            "@typescript-eslint/no-explicit-any": "warn",

            // ----- General correctness -----
            eqeqeq: ["error", "smart"],
            "no-console": ["warn", { allow: ["warn", "error", "info"] }],
            "no-debugger": "error",
            "prefer-const": "warn",
        },
    },
);
