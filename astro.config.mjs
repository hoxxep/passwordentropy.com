// @ts-check
import {defineConfig} from "astro/config";
import tailwindcss from "@tailwindcss/vite";

// https://astro.build/config
export default defineConfig({
    site: 'https://isitworththetime.com',

    compressHTML: import.meta.env.PROD,

    integrations: [],

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
