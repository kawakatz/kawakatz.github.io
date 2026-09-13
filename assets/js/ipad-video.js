export function videoViewport(corners) {
  if (corners.some(point => !Number.isFinite(point.x + point.y))) return null;
  const length = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
  const width = Math.min(length(corners[0], corners[1]), length(corners[3], corners[2]));
  const height = Math.min(length(corners[0], corners[3]), length(corners[1], corners[2]));
  const layoutWidth = Math.max(356, Math.ceil(width));
  return width > 0 && height > 0 ? { width: layoutWidth, height: Math.ceil(layoutWidth * 9 / 16) } : null;
}

export function createIPadVideo(iframe) {
  const clip = { videoId: '7A5YWn33eps', startSeconds: 0, endSeconds: 31 };
  const url = new URL(`https://www.youtube-nocookie.com/embed/${clip.videoId}`);
  url.search = new URLSearchParams({ enablejsapi: '1', controls: '1', playsinline: '1', end: String(clip.endSeconds), origin: location.origin });
  let player, script, ready = false, disposed = false, autoplay = false, applied;
  let userPaused = false, manualPlay = false, playPending = false, pausePending = false, state;
  let captionsInitialized = false;
  const sync = () => {
    if (disposed) return;
    const playing = manualPlay || autoplay && !userPaused;
    if (!ready || applied === playing) return;
    applied = playing;
    if (playing) {
      playPending = true;
      if (state === 0) player.loadVideoById(clip);
      else player.playVideo();
    }
    else { pausePending = state === 1 || state === 3 || playPending; player.pauseVideo(); }
  };
  function mount() {
    if (disposed || player) return;
    iframe.src = url.href;
    player = new window.YT.Player(iframe, { events: {
      onReady(event) {
        if (disposed) return;
        player = event.target; player.mute(); ready = true; sync();
      },
      onApiChange(event) {
        // The track option is undocumented; use it only when the player exposes it.
        if (disposed || captionsInitialized || !event.target.getOptions('captions').includes('track')) return;
        captionsInitialized = true;
        event.target.setOption('captions', 'track', {});
      },
      onStateChange(event) {
        if (disposed || !ready) return;
        if (event.data === 0 && playPending) return;
        state = event.data;
        if (event.data === 1 || event.data === 3) {
          const pending = playPending;
          // Initialize before first playback only; later manual caption choices take precedence.
          if (event.data === 1) { playPending = false; captionsInitialized = true; }
          // Respect reduced motion if it changes while a play command is pending.
          if (applied === false && pending) { applied = undefined; sync(); }
          else if (event.data === 1) {
            if (applied === false) { manualPlay = true; userPaused = false; }
            applied = true;
          }
        } else if (event.data === 0) {
          // Reapply the clip boundary each time; native playlist looping drops it after the first pass.
          playPending = pausePending = false; applied = undefined;
          sync();
        } else if (event.data === 2) {
          if (!pausePending && applied !== false) { userPaused = true; manualPlay = false; }
          playPending = pausePending = false; applied = false;
          sync();
        }
      },
      onAutoplayBlocked() { playPending = false; },
    } });
  }
  return {
    setPlaying(value) {
      if (disposed) return;
      autoplay = value;
      if (!iframe.hidden && !player && !script) {
        if (window.YT?.Player) mount();
        else {
          window.onYouTubeIframeAPIReady = mount;
          script = document.createElement('script');
          script.src = 'https://www.youtube.com/iframe_api';
          script.async = true;
          script.onerror = () => { if (!disposed) iframe.src = url.href; };
          document.head.append(script);
        }
      }
      sync();
    },
    dispose() {
      if (disposed) return;
      disposed = true; player?.destroy(); script?.remove();
      iframe.removeAttribute('src');
      if (window.onYouTubeIframeAPIReady === mount) delete window.onYouTubeIframeAPIReady;
    },
  };
}
