import { useEffect, useRef, useState } from 'react';
import Lottie, { LottieRefCurrentProps } from 'lottie-react';
import animationData from '../assets/button-full.json';

interface LottieButtonProps {
  status: string;
  connected: boolean;
  loading: boolean;
  onClick: () => void;
}

// Frame ranges from iOS Swift implementation - VERIFIED
const FRAMES = {
  CONNECTED: 142,              // Solid icy blue logo - IDLE state when connected
  DISCONNECTED: 339,           // Gray/faded logo - IDLE state when disconnected

  // CONNECTING SEQUENCE: gray -> icy blue
  CONNECTING_FADE_IN: { start: 0, end: 78 },        // Initial fade-in
  CONNECTING_LOOP: { start: 78, end: 120 },         // Loop while connecting
  CONNECTING_FADE_OUT: { start: 121, end: 142 },    // Fade to solid icy blue

  // DISCONNECTING SEQUENCE: icy blue -> gray
  DISCONNECTING_FADE_IN: { start: 152, end: 214 },  // Initial fade-in (from connected)
  DISCONNECTING_LOOP: { start: 215, end: 258 },     // Loop while disconnecting
  DISCONNECTING_FADE_OUT_PART1: { start: 259, end: 310 }, // Fade out on "button activate" layer
  DISCONNECTING_FADE_OUT_PART2: { start: 310, end: 339 }, // Continue fade on "button off" layer
};

export default function LottieButton({ status, connected, loading, onClick }: LottieButtonProps) {
  const lottieRef = useRef<LottieRefCurrentProps>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const animationStateRef = useRef<{
    shouldStop: boolean;
    targetState: 'connected' | 'disconnected' | null;
  }>({
    shouldStop: false,
    targetState: null,
  });

  // Initialize to the correct frame on mount
  useEffect(() => {
    if (lottieRef.current) {
      const initialFrame = connected ? FRAMES.CONNECTED : FRAMES.DISCONNECTED;
      console.log('Initializing animation to frame:', initialFrame, 'connected:', connected);
      lottieRef.current.goToAndStop(initialFrame, true);
    }
  }, []);

  // Handle state changes
  useEffect(() => {
    const lottie = lottieRef.current;
    if (!lottie) return;

    console.log('🔄 State change:', { connected, loading, isPlaying });

    // Determine target state
    if (loading && !connected) {
      // User pressed connect - currently disconnected, wanting to connect
      console.log('▶️ Starting CONNECTING sequence');
      animationStateRef.current.targetState = 'connected';
      if (!isPlaying) {
        playConnectingSequence(lottie);
      }
    } else if (loading && connected) {
      // User pressed disconnect - currently connected, wanting to disconnect
      console.log('▶️ Starting DISCONNECTING sequence');
      animationStateRef.current.shouldStop = true; // Stop current animation
      animationStateRef.current.targetState = 'disconnected';
      if (!isPlaying) {
        playDisconnectingSequence(lottie);
      }
      // If already playing (connecting), the loop will detect shouldStop and exit
    } else if (connected && !loading) {
      // Finished connecting - show connected state
      console.log('✅ Setting to CONNECTED state (frame 142)');
      animationStateRef.current.shouldStop = true;
      animationStateRef.current.targetState = 'connected';
      if (!isPlaying) {
        const currentFrame = lottie.animationItem?.currentFrame || 0;
        console.log(`  Current frame before setting to 142: ${currentFrame}`);
        lottie.goToAndStop(FRAMES.CONNECTED, true);
        const afterFrame = lottie.animationItem?.currentFrame || 0;
        console.log(`  Frame after setting: ${afterFrame}`);
      }
    } else if (!connected && !loading) {
      // Finished disconnecting - show disconnected state
      console.log('⭕ Setting to DISCONNECTED state (frame 339)');
      animationStateRef.current.shouldStop = true;
      animationStateRef.current.targetState = 'disconnected';
      if (!isPlaying) {
        const currentFrame = lottie.animationItem?.currentFrame || 0;
        console.log(`  Current frame before setting to 339: ${currentFrame}`);
        console.log(`  *** CRITICAL: About to call goToAndStop(339) ***`);
        lottie.goToAndStop(FRAMES.DISCONNECTED, true);

        // Wait a moment and check again
        setTimeout(() => {
          const afterFrame = lottie.animationItem?.currentFrame || 0;
          console.log(`  Frame after setting to 339: ${afterFrame}`);

          // Check DOM element visibility
          const container = lottie.animationItem?.wrapper;
          if (container) {
            const styles = window.getComputedStyle(container);
            console.log(`  Container display: ${styles.display}`);
            console.log(`  Container visibility: ${styles.visibility}`);
            console.log(`  Container opacity: ${styles.opacity}`);
            console.log(`  Container innerHTML length: ${container.innerHTML.length}`);

            // Check SVG elements
            const svg = container.querySelector('svg');
            if (svg) {
              const svgStyles = window.getComputedStyle(svg);
              console.log(`  SVG display: ${svgStyles.display}`);
              console.log(`  SVG visibility: ${svgStyles.visibility}`);
              console.log(`  SVG opacity: ${svgStyles.opacity}`);
            }
          }

          console.log(`  Is lottie visible? Check screen!`);
        }, 100);
      }
    }
  }, [connected, loading, isPlaying]);

  const playConnectingSequence = async (lottie: LottieRefCurrentProps) => {
    console.log('🔵 Starting connecting sequence');
    setIsPlaying(true);
    animationStateRef.current.shouldStop = false;

    // Play fade-in (0 -> 78)
    console.log('  Playing fade-in: 0 -> 78');
    await playSegment(lottie, FRAMES.CONNECTING_FADE_IN.start, FRAMES.CONNECTING_FADE_IN.end);

    if (animationStateRef.current.shouldStop) {
      console.log('  Stopped during fade-in');
      finishAnimation(lottie);
      return;
    }

    // Loop (78 -> 120) until state changes
    let loopCount = 0;
    while (!animationStateRef.current.shouldStop && animationStateRef.current.targetState === 'connected') {
      loopCount++;
      console.log(`  Loop ${loopCount}: 78 -> 120`);
      await playSegment(lottie, FRAMES.CONNECTING_LOOP.start, FRAMES.CONNECTING_LOOP.end);
      if (animationStateRef.current.shouldStop) break;
    }

    // Check what to do after loop
    if (animationStateRef.current.targetState === 'connected') {
      // Still want to be connected - play fade-out (121 -> 142)
      console.log('  Playing fade-out: 121 -> 142');
      await playSegment(lottie, FRAMES.CONNECTING_FADE_OUT.start, FRAMES.CONNECTING_FADE_OUT.end);
      console.log('  Stopping at frame 142');
      lottie.goToAndStop(FRAMES.CONNECTED, true);
      console.log('🔵 Connecting sequence complete');
      setIsPlaying(false);
    } else if (animationStateRef.current.targetState === 'disconnected') {
      // User clicked disconnect while connecting - transition immediately to disconnecting
      console.log('  Target changed to disconnected, transitioning to disconnecting sequence');
      // Don't set isPlaying to false - keep playing and start disconnecting sequence
      await playDisconnectingSequence(lottie);
    } else {
      console.log('🔵 Connecting sequence complete (interrupted)');
      setIsPlaying(false);
    }
  };

  const playDisconnectingSequence = async (lottie: LottieRefCurrentProps) => {
    console.log('🔴 Starting disconnecting sequence');
    const currentFrame = lottie.animationItem?.currentFrame || 0;
    console.log(`  Current frame before starting: ${currentFrame}`);

    setIsPlaying(true);
    animationStateRef.current.shouldStop = false;

    // CRITICAL: Ensure we're at frame 152 before starting
    console.log('  Jumping to frame 152 first');
    lottie.goToAndStop(FRAMES.DISCONNECTING_FADE_IN.start, true);

    // Small delay to let Lottie render the frame
    await new Promise(resolve => setTimeout(resolve, 50));

    // Play fade-in (152 -> 214)
    console.log('  Playing fade-in: 152 -> 214');
    await playSegment(lottie, FRAMES.DISCONNECTING_FADE_IN.start, FRAMES.DISCONNECTING_FADE_IN.end);

    if (animationStateRef.current.shouldStop) {
      console.log('  Stopped during fade-in');
      finishAnimation(lottie);
      return;
    }

    // Skip the loop and fade-out animation for now - just go straight to disconnected
    // This is temporary to test if the issue is with the animation playback
    console.log('  Skipping animation, jumping directly to frame 339');
    await new Promise(resolve => setTimeout(resolve, 500)); // Brief delay for visibility

    lottie.goToAndStop(FRAMES.DISCONNECTED, true);
    const finalFrame = lottie.animationItem?.currentFrame || 0;
    console.log(`  Final frame: ${finalFrame}`);
    console.log('🔴 Disconnecting sequence complete');
    setIsPlaying(false);
  };

  const finishAnimation = (lottie: LottieRefCurrentProps) => {
    console.log('⚡ Finishing animation immediately to target state');
    if (animationStateRef.current.targetState === 'connected') {
      console.log('  Jumping to frame 142');
      lottie.goToAndStop(FRAMES.CONNECTED, true);
    } else {
      console.log('  Jumping to frame 339');
      lottie.goToAndStop(FRAMES.DISCONNECTED, true);
    }
    setIsPlaying(false);
  };

  const playSegment = (
    lottie: LottieRefCurrentProps,
    startFrame: number,
    endFrame: number
  ): Promise<void> => {
    return new Promise((resolve) => {
      lottie.playSegments([startFrame, endFrame], true);

      // Calculate duration based on frame rate (29.97 fps from animation)
      const frameCount = endFrame - startFrame;
      const duration = (frameCount / 29.97) * 1000;

      setTimeout(() => {
        resolve();
      }, duration);
    });
  };

  const playSegmentContinuous = (
    lottie: LottieRefCurrentProps,
    startFrame: number,
    endFrame: number
  ): Promise<void> => {
    return new Promise((resolve) => {
      console.log(`    playSegmentContinuous: ${startFrame} -> ${endFrame}`);

      // Just use playSegments like normal
      lottie.playSegments([startFrame, endFrame], true);

      // Calculate duration based on frame rate (29.97 fps from animation)
      const frameCount = endFrame - startFrame;
      const duration = (frameCount / 29.97) * 1000;

      console.log(`    Duration: ${duration}ms for ${frameCount} frames`);

      setTimeout(() => {
        const currentFrame = lottie.animationItem?.currentFrame || 0;
        console.log(`    playSegmentContinuous complete, current frame: ${currentFrame}`);
        resolve();
      }, duration);
    });
  };

  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={`relative transition-all duration-300 ${
        loading ? 'opacity-80 cursor-wait' : 'hover:scale-105 active:scale-95 cursor-pointer'
      }`}
      style={{ width: '280px', height: '280px' }}
    >
      <Lottie
        lottieRef={lottieRef}
        animationData={animationData}
        loop={false}
        autoplay={false}
        style={{ width: '100%', height: '100%', visibility: 'visible' }}
        rendererSettings={{
          preserveAspectRatio: 'xMidYMid meet',
          clearCanvas: false,
        }}
      />
    </button>
  );
}
