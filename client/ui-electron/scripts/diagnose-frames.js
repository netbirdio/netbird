#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const animationPath = path.join(__dirname, '../src/assets/button-full.json');

console.log('Reading animation file...');
const animationData = JSON.parse(fs.readFileSync(animationPath, 'utf8'));

console.log('\n🔍 Checking frames 259-339 (disconnecting fade-out)...\n');

// Function to check opacity at specific frames
function checkOpacityAtFrames(obj, path = '', frameRange = { start: 259, end: 339 }) {
  const findings = [];

  function traverse(obj, currentPath = '') {
    if (Array.isArray(obj)) {
      obj.forEach((item, index) => traverse(item, `${currentPath}[${index}]`));
    } else if (obj && typeof obj === 'object') {
      // Check for opacity keyframes
      if (obj.o && obj.o.k) {
        const opacity = obj.o.k;

        // Animated opacity (keyframes)
        if (Array.isArray(opacity) && opacity[0] && typeof opacity[0] === 'object' && opacity[0].t !== undefined) {
          opacity.forEach((keyframe, idx) => {
            if (keyframe.t >= frameRange.start && keyframe.t <= frameRange.end) {
              const value = keyframe.s ? keyframe.s[0] : null;
              if (value !== null && value < 50) {
                findings.push({
                  path: currentPath,
                  frame: keyframe.t,
                  opacity: value,
                  type: 'keyframe'
                });
              }
            }
          });
        }
        // Static opacity
        else if (typeof opacity === 'number') {
          if (opacity < 50) {
            findings.push({
              path: currentPath,
              opacity: opacity,
              type: 'static'
            });
          }
        }
      }

      // Recursively process all properties
      for (const key in obj) {
        traverse(obj[key], `${currentPath}.${key}`);
      }
    }
  }

  traverse(obj, path);
  return findings;
}

// Check main layers
console.log('📊 Checking main layers:');
if (animationData.layers) {
  const findings = checkOpacityAtFrames(animationData.layers, 'layers');
  if (findings.length > 0) {
    console.log(`  ⚠️  Found ${findings.length} opacity issues:`);
    findings.forEach(f => {
      console.log(`    - ${f.path}`);
      console.log(`      ${f.type === 'keyframe' ? `Frame ${f.frame}:` : 'Static:'} opacity = ${f.opacity}`);
    });
  } else {
    console.log('  ✅ No low opacity values found in main layers');
  }
}

// Check assets (compositions)
console.log('\n📊 Checking asset compositions:');
if (animationData.assets) {
  animationData.assets.forEach((asset, idx) => {
    if (asset.layers) {
      const findings = checkOpacityAtFrames(asset.layers, `assets[${idx}].layers`);
      if (findings.length > 0) {
        console.log(`  ⚠️  Asset "${asset.nm || asset.id}" has ${findings.length} opacity issues:`);
        findings.forEach(f => {
          console.log(`    - ${f.path}`);
          console.log(`      ${f.type === 'keyframe' ? `Frame ${f.frame}:` : 'Static:'} opacity = ${f.opacity}`);
        });
      }
    }
  });
}

// Also check for in/out points that might hide layers during this range
console.log('\n📊 Checking layer in/out points (frames 259-339):');

function checkLayerTiming(layers, prefix = '') {
  const issues = [];
  layers.forEach((layer, idx) => {
    const layerName = layer.nm || `Layer ${idx}`;
    const inPoint = layer.ip !== undefined ? layer.ip : 0;
    const outPoint = layer.op !== undefined ? layer.op : 999;

    // Check if layer is hidden during our critical range (259-339)
    if (outPoint < 339 || inPoint > 259) {
      if (!(inPoint > 339 || outPoint < 259)) {
        // Layer is partially visible in our range
        issues.push({
          name: layerName,
          inPoint: inPoint,
          outPoint: outPoint,
          issue: outPoint < 339 ? `ends at frame ${outPoint} (before 339)` : `starts at frame ${inPoint} (after 259)`
        });
      }
    }
  });
  return issues;
}

if (animationData.layers) {
  const timingIssues = checkLayerTiming(animationData.layers);
  if (timingIssues.length > 0) {
    console.log('  ⚠️  Found layers with timing issues:');
    timingIssues.forEach(issue => {
      console.log(`    - "${issue.name}": in=${issue.inPoint}, out=${issue.outPoint}`);
      console.log(`      Issue: ${issue.issue}`);
    });
  } else {
    console.log('  ✅ All main layers are visible throughout frames 259-339');
  }
}

if (animationData.assets) {
  animationData.assets.forEach((asset, idx) => {
    if (asset.layers) {
      const timingIssues = checkLayerTiming(asset.layers);
      if (timingIssues.length > 0) {
        console.log(`  ⚠️  Asset "${asset.nm || asset.id}" has timing issues:`);
        timingIssues.forEach(issue => {
          console.log(`    - "${issue.name}": in=${issue.inPoint}, out=${issue.outPoint}`);
          console.log(`      Issue: ${issue.issue}`);
        });
      }
    }
  });
}

console.log('\n✅ Diagnosis complete!');
