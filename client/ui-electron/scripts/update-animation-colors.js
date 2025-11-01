#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const animationPath = path.join(__dirname, '../src/assets/button-full.json');

console.log('Reading animation file...');
const animationData = JSON.parse(fs.readFileSync(animationPath, 'utf8'));

// Icy blue color: #a3d7e5 -> RGB normalized: [0.639, 0.843, 0.898]
const ICY_BLUE = [0.639, 0.843, 0.898, 1];

// Orange colors to replace (normalized RGB):
// - 0.964705944061, 0.51372551918, 0.1882353127 (primary orange)
// - 0.952941236309, 0.36862745098, 0.196078446332 (secondary orange)
// - 0.952941179276, 0.368627458811, 0.196078434587 (another variant)

function isOrangeColor(color) {
  if (!Array.isArray(color) || color.length < 3) return false;
  const [r, g, b] = color;
  // Check if it's orange-ish (high red, medium green, low blue)
  return r > 0.85 && g > 0.3 && g < 0.6 && b < 0.3;
}

// Function to recursively find and modify orange colors
function replaceOrangeWithIcyBlue(obj, path = '') {
  if (Array.isArray(obj)) {
    return obj.map((item, index) => replaceOrangeWithIcyBlue(item, `${path}[${index}]`));
  } else if (obj && typeof obj === 'object') {
    // Check if this object has a color property 'c' with keyframe data 'k'
    if (obj.c && obj.c.k) {
      const color = obj.c.k;

      // Handle static color (array)
      if (Array.isArray(color) && isOrangeColor(color)) {
        console.log(`  Replacing orange color at ${path} -> icy blue`);
        obj.c.k = [...ICY_BLUE];
      }

      // Handle animated color (keyframes)
      if (Array.isArray(color) && color[0] && color[0].s) {
        color.forEach((keyframe, idx) => {
          if (keyframe.s && isOrangeColor(keyframe.s)) {
            console.log(`  Replacing orange keyframe at ${path}.c.k[${idx}].s -> icy blue`);
            keyframe.s = [...ICY_BLUE];
          }
          if (keyframe.e && isOrangeColor(keyframe.e)) {
            console.log(`  Replacing orange keyframe at ${path}.c.k[${idx}].e -> icy blue`);
            keyframe.e = [...ICY_BLUE];
          }
        });
      }
    }

    // Recursively process all properties
    const result = {};
    for (const key in obj) {
      result[key] = replaceOrangeWithIcyBlue(obj[key], `${path}.${key}`);
    }
    return result;
  }
  return obj;
}

console.log('Replacing orange colors with icy blue (#a3d7e5)...');

// Process layers
if (animationData.layers) {
  animationData.layers = replaceOrangeWithIcyBlue(animationData.layers, 'layers');
}

// Process assets (compositions)
if (animationData.assets) {
  animationData.assets = animationData.assets.map((asset, idx) => {
    if (asset.layers) {
      asset.layers = replaceOrangeWithIcyBlue(asset.layers, `assets[${idx}].layers`);
    }
    return asset;
  });
}

console.log('Writing updated animation...');
fs.writeFileSync(animationPath, JSON.stringify(animationData, null, 2));

console.log('✓ Animation colors updated to icy blue theme!');
