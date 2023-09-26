// Copyright (C) 2023 Storx Labs, Inc.
// See LICENSE for copying information.

/**
 * plugins/webfontloader.ts
 *
 * webfontloader documentation: https://github.com/typekit/webfontloader
 */

export async function loadFonts () {
    const webFontLoader = await import(/* webpackChunkName: "webfontloader" */'webfontloader');

    webFontLoader.load({
        google: {
            families: ['Inter:400,500,700&display=swap'],
        },
    });
}
