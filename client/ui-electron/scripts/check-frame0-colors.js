const fs = require('fs');
const data = JSON.parse(fs.readFileSync('./src/assets/button-full.json', 'utf8'));

// Check frame 0 colors - this should be in the first asset
const asset0 = data.assets[0]; // button start connecting (frames 0-78)
console.log('Asset 0:', asset0.nm);

// Look at layer 0 which has the main shapes
const layer0 = asset0.layers[0];
console.log('\nLayer 0:', layer0.nm);

if (layer0.shapes) {
  layer0.shapes.forEach((shape, idx) => {
    console.log(`\nShape ${idx}:`, shape.nm || 'unnamed');
    if (shape.it) {
      shape.it.forEach((item, iIdx) => {
        if (item.ty === 'fl' && item.c) {
          console.log(`  Item ${iIdx} (fill):`);
          console.log(`    Color:`, item.c.k);
          if (item.c.k && Array.isArray(item.c.k) && item.c.k[0] && item.c.k[0].t !== undefined) {
            console.log(`    Keyframes:`, item.c.k.length);
            item.c.k.slice(0, 3).forEach(kf => {
              console.log(`      Frame ${kf.t}: start =`, kf.s);
            });
          }
        }
      });
    }
  });
}
