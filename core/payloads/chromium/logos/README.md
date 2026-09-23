# Chromium logo references

These unmodified PNGs come from Chromium tag `153.0.8010.52`:

`https://github.com/chromium/chromium/tree/153.0.8010.52/chrome/app/theme`

Each `product_logo_<size>_<scale>.png` is the upstream file
`default_<scale>_percent/chromium/product_logo_<size>.png`.
The size is logical: a 32px logo at 200% has 64x64 physical pixels.
Chromium's BSD license is included in `LICENSE` and shipped in the release
license bundle. These references identify upstream artwork; they are not
displayed as Nomad's branding.

The launcher matches decoded RGBA pixels and dimensions, not PNG compression
or grit resource IDs. It requires exactly one matching canonical resource per
logo in each PAK. Aliases keep pointing to that canonical resource. A changed
logo or an ambiguous match fails closed and requires a reviewed reference
update. The grayscale replacement is also accepted for idempotent retries.

Source SHA-256 values:

| File | SHA-256 |
|---|---|
| product_logo_16_100.png | 32ea0cf8a4f67b8fde3225391201f72bb4ef117295b104961c68d0502a7142d8 |
| product_logo_16_200.png | 9fef85f58e6e4a2cdcbe8b0d3d8fe833547362ab1501ab700d745876fd830f4e |
| product_logo_32_100.png | c29f2c754d619246062db49e4ba1c3b8e96fcce18ec4524f5ef371172af385ad |
| product_logo_32_200.png | 926700351f770f2ae5d1298c75aa269da1416d1511e90a1eed07a5ac5e27e85e |
