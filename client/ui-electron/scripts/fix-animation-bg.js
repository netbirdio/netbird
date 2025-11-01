#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const animationPath = path.join(__dirname, '../src/assets/button-full.json');

console.log('Reading animation file...');
const animationData = JSON.parse(fs.readFileSync(animationPath, 'utf8'));

// Function to recursively find and modify background layers
function removeBackgrounds(obj) {
  if (Array.isArray(obj)) {
    return obj.map(item => removeBackgrounds(item));
  } else if (obj && typeof obj === 'object') {
    // Check if this is a layer with "Shape Layer" in the name
    if (obj.nm && (obj.nm.includes('Shape Layer') || obj.nm.includes('background'))) {
      console.log(`Found potential background layer: ${obj.nm}`);

      // Look for fill color in shapes
      if (obj.shapes) {
        obj.shapes = obj.shapes.map(shape => {
          if (shape.it) {
            shape.it = shape.it.map(item => {
              // If it's a fill with white/light color, make it transparent
              if (item.ty === 'fl' && item.c && item.c.k) {
                const color = item.c.k;
                // Check if it's a white or very light gray (close to 1.0 in RGB)
                if (Array.isArray(color) && color.length >= 3) {
                  const [r, g, b] = color;
                  if (r > 0.8 && g > 0.8 && b > 0.8) {
                    console.log(`  Removing white fill from ${obj.nm}`);
                    item.o = { a: 0, k: 0, ix: 5 }; // Set opacity to 0
                  }
                }
              }
              return item;
            });
          }
          return shape;
        });
      }
    }

    // Recursively process all properties
    const result = {};
    for (const key in obj) {
      result[key] = removeBackgrounds(obj[key]);
    }
    return result;
  }
  return obj;
}

console.log('Processing animation layers...');
animationData.layers = removeBackgrounds(animationData.layers);

// Also check for asset compositions
if (animationData.assets) {
  console.log('Processing animation assets...');
  animationData.assets = animationData.assets.map(asset => {
    if (asset.layers) {
      asset.layers = removeBackgrounds(asset.layers);
    }
    return asset;
  });
}

console.log('Writing modified animation...');
fs.writeFileSync(animationPath, JSON.stringify(animationData, null, 2));

console.log('✓ Animation background modified successfully!');
