#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const animationPath = path.join(__dirname, '../src/assets/button-full.json');

console.log('Reading animation file...');
const animationData = JSON.parse(fs.readFileSync(animationPath, 'utf8'));

// Icy blue color: #a3d7e5 -> RGB normalized: [0.639, 0.843, 0.898]
const ICY_BLUE = [0.639, 0.843, 0.898, 1];

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

console.log('\n🎨 Replacing orange colors with icy blue (#a3d7e5)...\n');
console.log('Only processing connecting/active states (not disconnected state)\n');

// Process assets (compositions)
if (animationData.assets) {
  animationData.assets.forEach((asset, idx) => {
    // Only replace colors in these precomps (NOT in "button off" which is the gray disconnected state)
    const shouldProcess = [
      'button start connecting',  // comp_0: frames 0-78
      'connecting loop',           // comp_1: frames 78-120
      'connecting to active',      // comp_2: frames 120-150
      'button activate',           // comp_3: frames 150-310 (connected state)
    ].includes(asset.nm || asset.id);

    if (shouldProcess && asset.layers) {
      console.log(`📦 Processing asset "${asset.nm || asset.id}"...`);
      asset.layers = replaceOrangeWithIcyBlue(asset.layers, `assets[${idx}].layers`);
    } else if (asset.nm === 'button off' || asset.id === 'comp_4') {
      console.log(`⏭️  Skipping asset "${asset.nm || asset.id}" (keeping gray disconnected state)`);
    }
  });
}

// Also process main layers (though they're just references to precomps)
if (animationData.layers) {
  console.log('\n📦 Processing main timeline layers...');
  animationData.layers = replaceOrangeWithIcyBlue(animationData.layers, 'layers');
}

console.log('\nWriting updated animation...');
fs.writeFileSync(animationPath, JSON.stringify(animationData, null, 2));

console.log('✅ Animation colors updated!');
console.log('   - Connecting/active states: icy blue (#a3d7e5)');
console.log('   - Disconnected state: original gray');
