// @ts-check
import {defineConfig} from "astro/config";
import tailwindcss from "@tailwindcss/vite";

// @ts-ignore
import astroBrokenLinksChecker from "astro-broken-link-checker";

// https://astro.build/config
export default defineConfig({
    site: 'https://passwordentropy.com',

    compressHTML: import.meta.env.PROD,
    trailingSlash: "always",

    integrations: [
        astroBrokenLinksChecker({
            logFilePath: "broken-links.log",
            checkExternalLinks: process.env.CHECK_EXTERNAL_LINKS === "true",
            throwError: true, // Stop the build if broken links are found
        }),
    ],

    vite: {
        plugins: [
            tailwindcss(),
        ]
    },

    output: "static",

    build: {
        inlineStylesheets: "always",
    },

    devToolbar: {
        enabled: false
    },

    server: ({command}) => ({
        port: command === "dev" ? 4321 : 4321
    }),
});
